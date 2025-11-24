"""
Domain management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from src.api.schemas.domain import (
    DomainCreate,
    DomainUpdate,
    DomainResponse,
    DomainListResponse,
    DomainDetailResponse
)
from src.api.schemas.common import MessageResponse
from src.services.domain_service import DomainService
from src.api.dependencies import get_domain_service, get_db_manager
from src.data.database.duckdb_manager import DuckDBManager

router = APIRouter(redirect_slashes=False)


@router.post("", response_model=MessageResponse, status_code=201)
async def create_domain(
    domain_data: DomainCreate,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Create a new domain.

    Adds a domain to the database for scanning and monitoring.
    """
    service = get_domain_service(db)

    try:
        result = service.create_domain(
            domain=domain_data.domain,
            is_primary=domain_data.is_primary,
            notes=domain_data.notes,
            tags=domain_data.tags,
            contact_email=domain_data.contact_email,
            scan_frequency=domain_data.scan_frequency
        )

        return MessageResponse(
            success=True,
            message=f"✓ Added domain {domain_data.domain}"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("", response_model=DomainListResponse)
async def list_domains(
    limit: int = Query(20, ge=1, le=100),
    domain_type: Optional[str] = Query(None, regex="^(apex|subdomain)$"),
    primary_only: bool = False,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    List domains with optional filtering.

    Returns a paginated list of domains with optional filters
    for domain type and primary status.
    """
    service = get_domain_service(db)

    try:
        result = service.list_domains(
            limit=limit,
            domain_type=domain_type,
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
    db: DuckDBManager = Depends(get_db_manager)
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


@router.patch("/{domain}", response_model=MessageResponse)
async def update_domain(
    domain: str,
    domain_data: DomainUpdate,
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Update domain metadata.

    Updates domain information such as primary status, notes, and tags.
    """
    service = get_domain_service(db)

    try:
        service.update_domain(
            domain=domain,
            is_primary=domain_data.is_primary,
            notes=domain_data.notes,
            tags=domain_data.tags
        )

        return MessageResponse(
            success=True,
            message=f"✓ Updated domain {domain}"
        )
    except ValueError as e:
        raise HTTPException(status_code=404 if "not found" in str(e).lower() else 400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.delete("/{domain}", response_model=MessageResponse)
async def delete_domain(
    domain: str,
    force: bool = Query(False, description="Skip confirmation and delete immediately"),
    db: DuckDBManager = Depends(get_db_manager)
):
    """
    Delete a domain and all associated data.

    Permanently removes the domain and all related scan data,
    results, and alerts.
    """
    service = get_domain_service(db)

    try:
        result = service.delete_domain(domain, force=force)

        return MessageResponse(
            success=True,
            message=f"✓ Deleted domain {domain} and {result['deleted'].get('total_records_deleted', 0)} associated records"
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
