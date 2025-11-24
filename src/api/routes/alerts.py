"""
Security alert endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from src.api.schemas.alert import (
    AlertResponse,
    AlertListResponse,
    AlertStatisticsResponse
)
from src.services.alert_service import AlertService
from src.api.dependencies import get_alert_service, get_db_manager
from src.data.database.duckdb_manager import DuckDBManager

router = APIRouter(redirect_slashes=False)


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, regex="^(info|low|medium|high|critical)$"),
    domain: Optional[str] = None,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    List security alerts with optional filtering.

    Returns a paginated list of security alerts with optional
    filters for severity and domain.
    """
    service = get_alert_service(db)

    try:
        result = service.list_alerts(
            limit=limit,
            severity=severity,
            domain=domain
        )

        return AlertListResponse(
            alerts=result['alerts'],
            total=result['total']
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/statistics", response_model=AlertStatisticsResponse)
async def get_alert_statistics(
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Get alert statistics.

    Returns aggregated statistics about alerts including
    counts by severity, type, and tool.
    """
    service = get_alert_service(db)

    try:
        result = service.get_alert_statistics()

        return AlertStatisticsResponse(**result['statistics'])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Get alert details.

    Returns detailed information about a specific alert.
    """
    service = get_alert_service(db)

    try:
        result = service.get_alert(alert_id)

        return AlertResponse(**result['alert'])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
