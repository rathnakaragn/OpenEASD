"""
Domain management endpoints (read-only).

This module provides read-only API endpoints for domain information.
Write operations are handled through the CLI.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.schemas.domain import (
    DomainResponse,
    DomainListResponse,
)
from src.services.domain_service import DomainService
from src.services.exceptions import DomainNotFound, InvalidDomainFormat
from src.api.dependencies import get_domain_service

logger = logging.getLogger(__name__)

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
    try:
        result = service.list_domains(
            limit=limit,
            primary_only=primary_only
        )

        return DomainListResponse(
            domains=result['domains'],
            total_count=result['total_count'],
            has_more=result['has_more']
        )
    except Exception:
        logger.error("Unexpected error listing domains", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list domains")


@router.get("/{domain}", response_model=DomainResponse)
async def get_domain(
    domain: str,
    service: DomainService = Depends(get_domain_service)
):
    """
    Get detailed information about a specific domain.

    Returns domain metadata, scan history, and recent subdomains.
    """
    try:
        domain_obj = service.get_domain(domain)
        return domain_obj
    except InvalidDomainFormat:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    except DomainNotFound:
        raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")
    except Exception:
        logger.error(f"Error retrieving domain {domain}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve domain details")
