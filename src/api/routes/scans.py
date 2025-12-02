"""
Scan management endpoints (read-only).

This module provides read-only API endpoints for scan information.
Scan execution is handled through the CLI.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.scan import (
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse,
)
from src.services.scan_service import ScanService
from src.api.dependencies import get_scan_service

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    service: ScanService = Depends(get_scan_service)
):
    """
    List scan sessions.

    Returns a paginated list of recent scan sessions.
    """
    try:
        result = service.list_scans(limit=limit)

        return ScanListResponse(
            scans=result['scans'],
            total=result['total']
        )
    except ValueError as e:
        logger.warning(f"Invalid scan list request: {e}")
        raise HTTPException(status_code=400, detail="Invalid request parameters")
    except KeyError as e:
        logger.error(f"Missing expected field in scan response: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    service: ScanService = Depends(get_scan_service)
):
    """
    Get scan status.

    Returns the current status and metadata for a specific scan.
    """
    try:
        result = service.get_scan_status(scan_id)
        scan_data = result['scan']

        # Extract domain from domains array if needed
        if 'domains' in scan_data and not scan_data.get('domain'):
            scan_data['domain'] = scan_data['domains'][0] if scan_data['domains'] else None

        return ScanResponse(**scan_data)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    except KeyError as e:
        logger.error(f"Missing expected field in scan data {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan status")


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    service: ScanService = Depends(get_scan_service)
):
    """
    Get scan results.

    Returns detailed results including discovered subdomains
    and open ports for a specific scan.
    """
    try:
        result = service.get_scan_results(scan_id)

        return ScanResultsResponse(
            scan=result['scan'],
            subdomains=result['subdomains'],
            ports=result['ports']
        )
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    except KeyError as e:
        logger.error(f"Missing expected field in scan results {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan results")
