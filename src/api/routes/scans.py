"""
Scan management endpoints (full access).

This module provides full API endpoints for scan management.
Scans are executed asynchronously via ZeroMQ job queue.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, status
from src.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse,
    BatchScanCreate,
    BatchScanResponse,
    ScanRetryRequest,
)
from src.api.schemas.finding import FindingListResponse
from src.api.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Severity
from src.orchestrator.scan_service import ScanService
from src.orchestrator.findings_service import FindingsService
from src.orchestrator.domain_service import DomainService
from src.api.dependencies import (
    get_scan_service,
    get_scan_service_with_queue,
    get_domain_service,
    get_findings_service,
)


router = APIRouter(redirect_slashes=False)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    service: ScanService = Depends(get_scan_service)
):
    """
    List scan sessions.

    Returns a paginated list of recent scan sessions.
    """
    result = service.list_scans(limit=limit, offset=offset)

    return ScanListResponse(
        scans=result['scans'],
        total_count=result['total_count'],
        limit=limit,
        offset=offset,
        has_more=result['has_more']
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {
            "description": "Scan queued for async execution",
            "headers": {
                "Location": {
                    "description": "URL to poll for scan status",
                    "schema": {"type": "string"}
                }
            }
        }
    }
)
async def create_scan(
    data: ScanCreate,
    response: Response,
    service: ScanService = Depends(get_scan_service_with_queue)
):
    """
    Create a new scan (async).

    Creates a scan record and queues it for async execution.
    Returns immediately with scan_id. Poll GET /scans/{scan_id} for status.

    The Location header in the response points to the status endpoint.
    """
    # Create scan record and queue for async processing
    scan = service.create_and_queue_scan(
        domain=data.domain,
        timeout=data.timeout
    )

    # Set Location header per RFC 7231 for 202 Accepted
    response.headers["Location"] = f"/api/v1/scans/{scan['scan_id']}"

    return ScanResponse(
        scan_id=scan['scan_id'],
        domain=data.domain,
        scan_type=scan.get('scan_type', 'full_scan'),
        tool_name=scan.get('tool_name'),
        status='pending',
        start_time=None,
        end_time=None,
        findings_count=0
    )


@router.post(
    "/batch",
    response_model=BatchScanResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def create_batch_scan(
    data: BatchScanCreate,
    service: ScanService = Depends(get_scan_service_with_queue),
    domain_service: DomainService = Depends(get_domain_service)
):
    """
    Create batch scans for multiple domains (async).

    Scans all registered domains (or only primary domains if primary_only=true).
    Each domain gets its own scan job in the queue.

    Returns list of scan IDs for polling.
    """
    # Get domains to scan
    domains_result = domain_service.list_domains(
        limit=1000,
        primary_only=data.primary_only
    )
    domains = domains_result.get('domains', [])

    if not domains:
        return BatchScanResponse(
            scans=[],
            total_queued=0,
            message="No domains found to scan"
        )

    # Queue all scans via service
    scans = service.queue_batch_scans(domains=domains, timeout=data.timeout)

    scan_responses = [
        ScanResponse(
            scan_id=scan['scan_id'],
            domain=scan['domain'],
            scan_type=scan.get('scan_type', 'full_scan'),
            tool_name=scan.get('tool_name'),
            status='pending',
            start_time=None,
            end_time=None,
            findings_count=0
        )
        for scan in scans
    ]

    return BatchScanResponse(
        scans=scan_responses,
        total_queued=len(scan_responses),
        message=f"Queued {len(scan_responses)} scans for processing"
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
    return ScanResponse(**result['scan'])


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


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    service: ScanService = Depends(get_scan_service)
):
    """
    Delete a scan and all associated data.

    Removes a scan session and all related findings and tool results.
    Cannot delete scans that are currently running - cancel them first.
    """
    service.delete_scan(scan_id)
    return None


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: str,
    service: ScanService = Depends(get_scan_service)
):
    """
    Cancel a pending or running scan.

    Updates the scan status to 'cancelled' and prevents further execution.
    Can only cancel scans that are pending or running.
    """
    result = service.cancel_scan(scan_id)
    return ScanResponse(**result['scan'])


@router.post(
    "/{scan_id}/retry",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def retry_scan(
    scan_id: str,
    data: ScanRetryRequest,
    response: Response,
    service: ScanService = Depends(get_scan_service_with_queue)
):
    """
    Retry a failed scan.

    Creates a new scan for the same domain and queues it for execution.
    Can only retry scans that have failed.

    Returns the new scan information with 202 Accepted status.
    """
    # Retry the scan and queue for processing
    retry_result = service.retry_and_queue_scan(scan_id, timeout=data.timeout)

    # Set Location header for the new scan
    response.headers["Location"] = f"/api/v1/scans/{retry_result['new_scan_id']}"

    # Get the new scan details
    scan_status = service.get_scan_status(retry_result['new_scan_id'])

    return ScanResponse(**scan_status['scan'])


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(
    scan_id: str,
    min_severity: Optional[Severity] = Query(None, description="Minimum severity filter (critical, high, medium, low, info)"),
    limit: int = Query(100, ge=1, le=1000, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    service: ScanService = Depends(get_scan_service),
    findings_service: FindingsService = Depends(get_findings_service)
):
    """
    Get findings for a specific scan.

    RESTful alternative to /findings/scan/{id}.
    Returns security findings discovered during this scan.
    """
    result = findings_service.get_findings_by_scan(
        scan_id=scan_id,
        min_severity=min_severity,
        limit=limit,
        offset=offset
    )

    return FindingListResponse(**result)
