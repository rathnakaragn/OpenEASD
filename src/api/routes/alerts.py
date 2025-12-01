"""
Security alert endpoints.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from src.api.schemas.alert import (
    AlertResponse,
    AlertListResponse,
    AlertStatisticsResponse
)
from src.services.alert_service import AlertService
from src.api.dependencies import get_alert_service, get_db_manager
from src.data.database.sqlmodel_manager import SQLModelManager

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, pattern="^(info|low|medium|high|critical)$"),
    domain: Optional[str] = None,
    min_severity: Optional[str] = Query(None, pattern="^(info|low|medium|high|critical)$"),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    List security alerts with optional filtering.

    Returns a paginated list of security alerts with optional
    filters for severity, domain, and minimum severity level.

    **Parameters:**
    - **limit**: Maximum number of alerts (1-200, default: 50)
    - **severity**: Filter by exact severity level
    - **domain**: Filter by domain/subdomain
    - **min_severity**: Minimum severity level (excludes lower severity)

    **Note**: Now powered by Analysis Layer for enhanced risk scoring.
    """
    service = get_alert_service(db)

    try:
        result = service.list_alerts(
            limit=limit,
            severity=severity,
            domain=domain,
            min_severity=min_severity
        )

        return AlertListResponse(
            alerts=result['alerts'],
            total=result['total']
        )
    except ValueError as e:
        logger.warning(f"Invalid alert filter: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error listing alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list alerts")


@router.get("/statistics", response_model=AlertStatisticsResponse)
async def get_alert_statistics(
    db: SQLModelManager = Depends(get_db_manager)
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
        logger.error(f"Error retrieving alert statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert statistics")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Get alert details by ID.

    Returns detailed information about a specific alert.
    """
    service = get_alert_service(db)

    try:
        result = service.get_alert(alert_id)

        return AlertResponse(**result['alert'])
    except ValueError as e:
        logger.info(f"Alert not found: {alert_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert details")
