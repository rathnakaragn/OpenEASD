"""
Findings API routes.

Provides endpoints for retrieving and managing security findings
from the Analysis Layer.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingStatisticsResponse,
    FindingStatusUpdate
)
from src.api.dependencies import get_db_manager
from src.data.database.sqlmodel_manager import SQLModelManager


router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", response_model=FindingListResponse)
async def list_findings(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    affected_asset: Optional[str] = Query(None, description="Filter by affected asset"),
    min_severity: Optional[str] = Query(
        None,
        description="Minimum severity (critical/high/medium/low/info)"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: SQLModelManager = Depends(get_db_manager)
) -> FindingListResponse:
    """
    List findings with optional filters.

    Retrieve security findings discovered during scans, with filtering
    by scan ID, affected asset, and minimum severity level.

    **Parameters:**
    - **scan_id**: Filter findings from a specific scan
    - **affected_asset**: Filter findings for a specific domain/subdomain/IP
    - **min_severity**: Show only findings at or above this severity level
    - **limit**: Number of results per page (1-1000, default: 100)
    - **offset**: Skip this many results (for pagination)

    **Returns:**
    - List of findings with pagination metadata
    """
    try:
        result = db.get_findings(
            scan_id=scan_id,
            affected_asset=affected_asset,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )

        return FindingListResponse(**result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve findings: {str(e)}")


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: SQLModelManager = Depends(get_db_manager)
) -> FindingResponse:
    """
    Get a specific finding by ID.

    Retrieve detailed information about a single security finding.

    **Parameters:**
    - **finding_id**: UUID of the finding

    **Returns:**
    - Finding details including evidence, risk score breakdown, and status
    """
    try:
        finding = db.get_finding_by_id(finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

        return FindingResponse(**finding)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve finding: {str(e)}")


@router.get("/statistics/summary", response_model=FindingStatisticsResponse)
async def get_findings_statistics(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    affected_asset: Optional[str] = Query(None, description="Filter by affected asset"),
    db: SQLModelManager = Depends(get_db_manager)
) -> FindingStatisticsResponse:
    """
    Get findings statistics.

    Retrieve aggregated statistics about security findings, including
    counts by severity and status.

    **Parameters:**
    - **scan_id**: Filter statistics for a specific scan
    - **affected_asset**: Filter statistics for a specific asset

    **Returns:**
    - Statistics including counts by severity, status, and risk scores
    """
    try:
        stats = db.get_findings_statistics(
            scan_id=scan_id,
            affected_asset=affected_asset
        )

        return FindingStatisticsResponse(**stats)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@router.patch("/{finding_id}/status", response_model=dict)
async def update_finding_status(
    finding_id: str,
    status_update: FindingStatusUpdate,
    db: SQLModelManager = Depends(get_db_manager)
) -> dict:
    """
    Update finding status.

    Update the status of a finding (e.g., mark as resolved or false positive).

    **Parameters:**
    - **finding_id**: UUID of the finding
    - **status_update**: New status and optional resolution notes

    **Valid statuses:**
    - **open**: Finding is open and needs attention
    - **acknowledged**: Finding has been acknowledged
    - **resolved**: Finding has been fixed
    - **false_positive**: Finding is a false positive

    **Returns:**
    - Success message
    """
    try:
        success = db.update_finding_status(
            finding_id=finding_id,
            status=status_update.status,
            resolution_notes=status_update.resolution_notes
        )

        if not success:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

        return {
            "success": True,
            "message": f"Finding {finding_id} status updated to {status_update.status}"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update finding status: {str(e)}"
        )


@router.get("/scan/{scan_id}", response_model=FindingListResponse)
async def get_scan_findings(
    scan_id: str,
    min_severity: Optional[str] = Query(
        None,
        description="Minimum severity (critical/high/medium/low/info)"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: SQLModelManager = Depends(get_db_manager)
) -> FindingListResponse:
    """
    Get findings for a specific scan.

    Retrieve all security findings discovered during a particular scan.

    **Parameters:**
    - **scan_id**: UUID of the scan session
    - **min_severity**: Show only findings at or above this severity level
    - **limit**: Number of results per page (1-1000, default: 100)
    - **offset**: Skip this many results (for pagination)

    **Returns:**
    - List of findings from the specified scan
    """
    try:
        result = db.get_findings(
            scan_id=scan_id,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )

        return FindingListResponse(**result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve scan findings: {str(e)}"
        )


@router.get("/asset/{asset_name}", response_model=FindingListResponse)
async def get_asset_findings(
    asset_name: str,
    min_severity: Optional[str] = Query(
        None,
        description="Minimum severity (critical/high/medium/low/info)"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: SQLModelManager = Depends(get_db_manager)
) -> FindingListResponse:
    """
    Get findings for a specific asset.

    Retrieve all security findings for a particular domain, subdomain, or IP.

    **Parameters:**
    - **asset_name**: Domain/subdomain/IP address
    - **min_severity**: Show only findings at or above this severity level
    - **limit**: Number of results per page (1-1000, default: 100)
    - **offset**: Skip this many results (for pagination)

    **Returns:**
    - List of findings affecting the specified asset
    """
    try:
        result = db.get_findings(
            affected_asset=asset_name,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )

        return FindingListResponse(**result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve asset findings: {str(e)}"
        )
