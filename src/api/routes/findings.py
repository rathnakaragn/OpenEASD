"""
Findings API routes (read-only).

Provides endpoints for retrieving security findings from the Analysis Layer.
Uses FindingsService for business logic. Status updates are handled through CLI.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingStatisticsResponse,
)
from src.api.dependencies import get_findings_service
from src.services.findings_service import FindingsService, FindingNotFound
import logging

logger = logging.getLogger(__name__)


router = APIRouter(tags=["findings"])


@router.get("", response_model=FindingListResponse)
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

    except ValueError as e:
        logger.warning(f"Invalid request parameters: {e}")
        raise HTTPException(status_code=400, detail="Invalid request parameters")
    except KeyError as e:
        logger.error(f"Missing expected field in findings response: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve findings")


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
    """
    try:
        stats = findings_service.get_statistics(
            scan_id=scan_id,
            affected_asset=affected_asset
        )
        return FindingStatisticsResponse(**stats)

    except ValueError as e:
        logger.warning(f"Invalid request parameters: {e}")
        raise HTTPException(status_code=400, detail="Invalid request parameters")
    except KeyError as e:
        logger.error(f"Missing expected field in statistics response: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


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
    """
    try:
        result = findings_service.get_findings_by_scan(
            scan_id=scan_id,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )
        return FindingListResponse(**result)

    except ValueError:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    except KeyError as e:
        logger.error(f"Missing expected field in scan findings for {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan findings")


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
    """
    try:
        result = findings_service.get_findings_by_asset(
            asset_name=asset_name,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )
        return FindingListResponse(**result)

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid asset name")
    except KeyError as e:
        logger.error(f"Missing expected field in asset findings for {asset_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve asset findings")


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    findings_service: FindingsService = Depends(get_findings_service)
) -> FindingResponse:
    """
    Get a specific finding by ID.

    Retrieve detailed information about a single security finding.
    """
    try:
        finding = findings_service.get_finding(finding_id)
        return FindingResponse(**finding)

    except FindingNotFound:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    except KeyError as e:
        logger.error(f"Missing expected field in finding {finding_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve finding")
