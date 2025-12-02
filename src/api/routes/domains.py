"""
Domain management endpoints (read-only).

This module provides read-only API endpoints for domain information.
Write operations are handled through the CLI.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from fastapi import APIRouter, Depends, Query
from src.api.schemas.domain import (
    DomainResponse,
    DomainListResponse,
    DomainDetailResponse,
)
from src.services.domain_service import DomainService
from src.api.dependencies import get_domain_service


router = APIRouter(redirect_slashes=False)


@router.get("", response_model=DomainListResponse)
async def list_domains(
    limit: int = Query(20, ge=1, le=100),
    primary_only: bool = False,
    service: DomainService = Depends(get_domain_service)
):
    """
    List domains with optional filtering.

    Returns a paginated list of domains with optional filters
    for primary status.
    """
    result = service.list_domains(
        limit=limit,
        primary_only=primary_only
    )

    return DomainListResponse(
        domains=result['domains'],
        total_count=result['total_count'],
        has_more=result['has_more']
    )


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
