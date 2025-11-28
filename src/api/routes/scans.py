"""
Scan management endpoints.

This module provides full API endpoints for scan management including
scan execution with authentication.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from src.api.schemas.scan import (
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse,
    ScanCreate
)
from src.services.scan_service import ScanService
from src.api.dependencies import get_scan_service, get_db_manager, verify_api_key, check_permission
from src.data.database.sqlmodel_manager import SQLModelManager

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    List scan sessions.

    Returns a paginated list of recent scan sessions.
    """
    service = get_scan_service(db)

    try:
        result = service.list_scans(limit=limit)

        return ScanListResponse(
            scans=result['scans'],
            total=result['total']
        )
    except ValueError as e:
        logger.warning(f"Invalid scan list request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error listing scans: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Get scan status.

    Returns the current status and metadata for a specific scan.
    """
    service = get_scan_service(db)

    try:
        result = service.get_scan_status(scan_id)
        scan_data = result['scan']

        # Extract domain from domains array if needed
        if 'domains' in scan_data and not scan_data.get('domain'):
            scan_data['domain'] = scan_data['domains'][0] if scan_data['domains'] else None

        return ScanResponse(**scan_data)
    except ValueError as e:
        logger.info(f"Scan not found: {scan_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error retrieving scan status {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan status")


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Get scan results.

    Returns detailed results including discovered subdomains
    and open ports for a specific scan.
    """
    service = get_scan_service(db)

    try:
        result = service.get_scan_results(scan_id)

        return ScanResultsResponse(
            scan=result['scan'],
            subdomains=result['subdomains'],
            ports=result['ports']
        )
    except ValueError as e:
        logger.info(f"Scan results not found: {scan_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error retrieving scan results {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan results")


@router.post("", response_model=ScanResponse, status_code=202)
async def execute_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    api_key_info: dict = Depends(verify_api_key),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Execute a scan (async, requires authentication).

    Creates a scan session and executes it in the background.
    Returns immediately with scan ID for status polling.

    Requires: API key with 'scan:execute' or '*' permission

    Note: This endpoint returns 202 Accepted and runs the scan
    in the background. Poll GET /scans/{scan_id} to check status.
    """
    # Check permission
    if not check_permission(api_key_info, "scan:execute"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'scan:execute' permission."
        )

    service = get_scan_service(db)

    try:
        # Execute scan in background (non-blocking)
        result = service.execute_scan_async(
            domain=scan_data.domain,
            timeout=scan_data.timeout,
            save=True
        )

        logger.info(f"Scan initiated via API: {scan_data.domain} (API key: {api_key_info.get('id')})")

        return ScanResponse(**result['scan'])

    except ValueError as e:
        logger.warning(f"Invalid scan request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error initiating scan for {scan_data.domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initiate scan")


@router.post("/{scan_id}/analysis", response_model=dict, status_code=202)
async def run_analysis(
    scan_id: str,
    background_tasks: BackgroundTasks,
    api_key_info: dict = Depends(verify_api_key),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Trigger analysis on completed scan (requires authentication).

    Runs analysis in the background to identify vulnerabilities
    and security findings from scan results.

    Requires: API key with 'scan:execute' or '*' permission

    Note: This endpoint returns 202 Accepted and runs analysis
    in the background. Check findings via GET /findings.
    """
    # Check permission
    if not check_permission(api_key_info, "scan:execute"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'scan:execute' permission."
        )

    service = get_scan_service(db)

    try:
        # Trigger analysis in background
        result = service.trigger_analysis(scan_id)

        logger.info(f"Analysis triggered via API for scan: {scan_id} (API key: {api_key_info.get('id')})")

        return {
            "message": "Analysis triggered successfully",
            "scan_id": scan_id,
            "status": "analyzing"
        }

    except ValueError as e:
        logger.info(f"Scan not found for analysis: {scan_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error triggering analysis for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to trigger analysis")
