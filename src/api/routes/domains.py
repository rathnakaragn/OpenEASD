"""
Domain management endpoints (full access).

This module provides full CRUD API endpoints for domain management.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from src.api.schemas.domain import (
    DomainCreate,
    DomainUpdate,
    DomainResponse,
    DomainListResponse,
    DomainDetailResponse,
)
from src.api.schemas.scan import ScanListResponse
from src.api.schemas.finding import FindingListResponse
from src.api.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Severity
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.findings_service import FindingsService
from src.api.dependencies import get_domain_service, get_scan_service, get_findings_service


router = APIRouter(redirect_slashes=False)


@router.get("", response_model=DomainListResponse)
async def list_domains(
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    primary_only: bool = Query(False, description="Only return primary domains"),
    service: DomainService = Depends(get_domain_service)
):
    """
    List domains with optional filtering.

    Returns a paginated list of domains with optional filters
    for primary status.
    """
    result = service.list_domains(
        limit=limit,
        offset=offset,
        primary_only=primary_only
    )

    return DomainListResponse(
        domains=result['domains'],
        total_count=result['total_count'],
        limit=result['limit'],
        offset=result['offset'],
        has_more=result['has_more']
    )


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    data: DomainCreate,
    service: DomainService = Depends(get_domain_service)
):
    """
    Create a new domain.

    Adds a new domain to the system for monitoring.
    """
    result = service.create_domain(
        domain=data.domain,
        is_primary=data.is_primary,
        contact_email=data.contact_email,
        scan_frequency=data.scan_frequency
    )
    return result


@router.get("/{domain}", response_model=DomainDetailResponse)
async def get_domain(
    domain: str,
    service: DomainService = Depends(get_domain_service)
):
    """
    Get detailed information about a specific domain.

    Returns domain metadata, scan history, and recent subdomains.
    """
    domain_obj = service.get_domain(domain)
    return domain_obj


@router.put("/{domain}", response_model=DomainResponse)
async def update_domain(
    domain: str,
    data: DomainUpdate,
    service: DomainService = Depends(get_domain_service)
):
    """
    Update domain metadata.

    Updates primary status, contact email, and scan frequency.
    At least one field must be provided.
    """
    result = service.update_domain(
        domain=domain,
        is_primary=data.is_primary,
        contact_email=data.contact_email,
        scan_frequency=data.scan_frequency
    )
    return result


@router.delete("/{domain}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain_endpoint(
    domain: str,
    service: DomainService = Depends(get_domain_service)
):
    """
    Delete a domain.

    Removes a domain and all associated data from the system.
    """
    service.delete_domain(domain)
    return None


@router.get("/{domain}/scans", response_model=ScanListResponse)
async def get_domain_scans(
    domain: str,
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    service: DomainService = Depends(get_domain_service),
    scan_service: ScanService = Depends(get_scan_service)
):
    """
    Get all scans for a specific domain.

    Returns a paginated list of scan sessions for the given domain.
    """
    # Verify domain exists
    service.get_domain(domain)

    # Get scans for this domain (filtered at database level)
    result = scan_service.list_scans(limit=limit, offset=offset, domain=domain)

    return ScanListResponse(
        scans=result['scans'],
        total_count=result['total_count'],
        limit=limit,
        offset=offset,
        has_more=result['has_more']
    )


@router.get("/{domain}/findings", response_model=FindingListResponse)
async def get_domain_findings(
    domain: str,
    min_severity: Optional[Severity] = Query(None, description="Minimum severity filter (critical, high, medium, low, info)"),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    service: DomainService = Depends(get_domain_service),
    findings_service: FindingsService = Depends(get_findings_service)
):
    """
    Get all findings for a domain (across all scans).

    Returns security findings for all scans of the given domain.
    """
    # Verify domain exists
    service.get_domain(domain)

    # Get findings for this domain
    result = findings_service.list_findings(
        affected_asset=domain,
        min_severity=min_severity,
        limit=limit,
        offset=offset
    )

    return FindingListResponse(**result)
