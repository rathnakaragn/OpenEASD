"""
Domain management endpoints (Read-Only).

This module provides read-only API endpoints for domain management.
For write operations (add, update, delete), use the CLI:
    openeasd domain add <domain>
    openeasd domain update <domain>
    openeasd domain remove <domain>
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from src.api.schemas.domain import (
    DomainResponse,
    DomainListResponse,
    DomainDetailResponse
)
from src.services.domain_service import DomainService
from src.api.dependencies import get_domain_service, get_db_manager
from src.data.database.sqlmodel_manager import SQLModelManager

router = APIRouter(redirect_slashes=False)

# Note: POST, PATCH, DELETE operations removed for security
# Use CLI for write operations: openeasd domain add/update/remove


@router.get("", response_model=DomainListResponse)
async def list_domains(
    limit: int = Query(20, ge=1, le=100),
    primary_only: bool = False,
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    List domains with optional filtering.

    Returns a paginated list of domains with optional filters
    for primary status.
    """
    service = get_domain_service(db)

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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/{domain}", response_model=DomainDetailResponse)
async def get_domain(
    domain: str,
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Get detailed information about a specific domain.

    Returns domain metadata, scan history, and recent subdomains.
    """
    service = get_domain_service(db)

    try:
        result = service.get_domain(domain)

        return DomainDetailResponse(
            **result['domain'],
            subdomain_count=result['subdomain_count'],
            recent_subdomains=result['recent_subdomains']
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Write operations removed for security (read-only API)
# For domain management operations, use the CLI:
#   openeasd domain add <domain> --primary --notes "..." --tags "..."
#   openeasd domain update <domain> --notes "..." --tags "..."
#   openeasd domain remove <domain>
