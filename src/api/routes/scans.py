"""
Scan management endpoints (read-only).

This module provides read-only API endpoints for scan information.
Scan execution is handled through the CLI.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from fastapi import APIRouter, Depends, Query
from src.api.schemas.scan import (
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse,
)
from src.services.scan_service import ScanService
from src.api.dependencies import get_scan_service


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
    result = service.list_scans(limit=limit)

    return ScanListResponse(
        scans=result['scans'],
        total=result['total']
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    service: ScanService = Depends(get_scan_service)
):
    """
    Get scan status.

    Returns the current status and metadata for a specific scan.
    """
    result = service.get_scan_status(scan_id)
    scan_data = result['scan']

    # Extract domain from domains array if needed
    if 'domains' in scan_data and not scan_data.get('domain'):
        scan_data['domain'] = scan_data['domains'][0] if scan_data['domains'] else None

    return ScanResponse(**scan_data)


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
    result = service.get_scan_results(scan_id)

    return ScanResultsResponse(
        scan=result['scan'],
        subdomains=result['subdomains'],
        ports=result['ports']
    )
