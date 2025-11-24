"""
Scan management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse
)
from src.services.scan_service import ScanService
from src.api.dependencies import get_scan_service, get_db_manager
from src.data.database.duckdb_manager import DuckDBManager

router = APIRouter(redirect_slashes=False)


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Create and execute a new scan.

    Initiates a complete reconnaissance scan for the specified domain
    including subdomain discovery, DNS resolution, and port scanning.
    """
    service = get_scan_service(db)

    try:
        # Execute scan
        result = service.execute_scan(
            domain=scan_data.domain,
            timeout=scan_data.timeout
        )

        # Get scan status
        scan_status = service.get_scan_status(result['scan_id'])

        return ScanResponse(**scan_status['scan'])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    db: DuckDBManager = Depends(get_db_manager)
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    db: DuckDBManager = Depends(get_db_manager)
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
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: str,
    db: DuckDBManager = Depends(get_db_manager)
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
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
