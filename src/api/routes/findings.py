"""
Findings API routes.

Provides endpoints for retrieving and managing security findings
from the Analysis Layer. Uses FindingsService for business logic.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingStatisticsResponse,
    FindingStatusUpdate
)
from src.api.dependencies import get_findings_service, verify_api_key, check_permission
from src.services.findings_service import FindingsService, FindingNotFound, InvalidFindingStatus
import logging

logger = logging.getLogger(__name__)


router = APIRouter(tags=["findings"], redirect_slashes=False)


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
    findings_service: FindingsService = Depends(get_findings_service)
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
        result = findings_service.list_findings(
            scan_id=scan_id,
            affected_asset=affected_asset,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )
        return FindingListResponse(**result)

    except Exception as e:
        logger.error(f"Failed to retrieve findings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve findings: {str(e)}")


@router.get("/statistics/summary", response_model=FindingStatisticsResponse)
async def get_findings_statistics(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    affected_asset: Optional[str] = Query(None, description="Filter by affected asset"),
    findings_service: FindingsService = Depends(get_findings_service)
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
        stats = findings_service.get_statistics(
            scan_id=scan_id,
            affected_asset=affected_asset
        )
        return FindingStatisticsResponse(**stats)

    except Exception as e:
        logger.error(f"Failed to retrieve statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
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
    findings_service: FindingsService = Depends(get_findings_service)
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
        result = findings_service.get_findings_by_scan(
            scan_id=scan_id,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )
        return FindingListResponse(**result)

    except Exception as e:
        logger.error(f"Failed to retrieve scan findings: {e}")
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
    findings_service: FindingsService = Depends(get_findings_service)
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
        result = findings_service.get_findings_by_asset(
            asset_name=asset_name,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )
        return FindingListResponse(**result)

    except Exception as e:
        logger.error(f"Failed to retrieve asset findings: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve asset findings: {str(e)}"
        )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    findings_service: FindingsService = Depends(get_findings_service)
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
        finding = findings_service.get_finding(finding_id)
        return FindingResponse(**finding)

    except FindingNotFound:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    except Exception as e:
        logger.error(f"Failed to retrieve finding: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve finding: {str(e)}")


@router.patch("/{finding_id}/status", response_model=dict)
async def update_finding_status(
    finding_id: str,
    status_update: FindingStatusUpdate,
    api_key_info: dict = Depends(verify_api_key),
    findings_service: FindingsService = Depends(get_findings_service)
) -> dict:
    """
    Update finding status.

    Update the status of a finding (e.g., mark as resolved or false positive).
    **Requires API key authentication with 'finding:write' or '*' permission.**

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
    # Check permission
    if not check_permission(api_key_info, "finding:write"):
        logger.warning(
            f"Permission denied: API key {api_key_info.get('name')} "
            f"attempted finding status update without permission"
        )
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'finding:write' or '*' permission."
        )

    try:
        result = findings_service.update_status(
            finding_id=finding_id,
            status=status_update.status,
            resolution_notes=status_update.resolution_notes
        )

        logger.info(
            f"Finding {finding_id} status updated to {status_update.status} "
            f"by API key: {api_key_info.get('name')}"
        )

        return result

    except FindingNotFound:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    except InvalidFindingStatus as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update finding status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update finding status: {str(e)}"
        )
