"""
Domain management endpoints.

This module provides full API endpoints for domain management including
write operations with authentication.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from src.api.schemas.domain import (
    DomainResponse,
    DomainListResponse,
    DomainDetailResponse,
    DomainCreate,
    DomainUpdate,
    MessageResponse
)
from src.services.domain_service import DomainService
from src.services.exceptions import DomainNotFound, DomainAlreadyExists, InvalidDomainFormat
from src.api.dependencies import get_domain_service, get_db_manager, verify_api_key, check_permission
from src.data.database.sqlmodel_manager import SQLModelManager

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


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
        logger.error(f"Unexpected error listing domains: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list domains")


@router.get("/{domain}", response_model=DomainResponse)
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
        domain_obj = service.get_domain(domain)
        return domain_obj
    except InvalidDomainFormat as e:
        raise HTTPException(status_code=400, detail=str(e))
    except DomainNotFound as e:
        logger.info(f"Domain not found: {domain}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error retrieving domain {domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve domain details")

@router.post("", response_model=DomainResponse, status_code=201)
async def create_domain(
    domain_data: DomainCreate,
    api_key_info: dict = Depends(verify_api_key),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Create a new domain (requires authentication).

    Creates a new domain entry with optional metadata like primary status,
    contact email, and scan frequency.

    Requires: API key with 'domain:write' or '*' permission
    """
    # Check permission
    if not check_permission(api_key_info, "domain:write"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'domain:write' permission."
        )

    service = get_domain_service(db)

    try:
        domain_obj = service.create_domain(
            domain=domain_data.domain,
            is_primary=domain_data.is_primary,
            contact_email=domain_data.contact_email,
            scan_frequency=domain_data.scan_frequency
        )

        logger.info(f"Created domain via API: {domain_data.domain} (API key: {api_key_info.get('id')})")

        return domain_obj

    except (InvalidDomainFormat, DomainAlreadyExists) as e:
        logger.warning(f"Invalid domain creation request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating domain {domain_data.domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to create domain")


@router.patch("/{domain}", response_model=DomainResponse)
async def update_domain(
    domain: str,
    update_data: DomainUpdate,
    api_key_info: dict = Depends(verify_api_key),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Update domain metadata (requires authentication).

    Updates domain properties like primary status.

    Requires: API key with 'domain:write' or '*' permission
    """
    # Check permission
    if not check_permission(api_key_info, "domain:write"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'domain:write' permission."
        )

    service = get_domain_service(db)

    try:
        domain_obj = service.update_domain(
            domain=domain,
            is_primary=update_data.is_primary
        )

        logger.info(f"Updated domain via API: {domain} (API key: {api_key_info.get('id')})")

        return domain_obj

    except (InvalidDomainFormat, DomainNotFound) as e:
        logger.info(f"Domain not found for update: {domain}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating domain {domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update domain")


@router.put("/{domain}")
async def update_domain_put(
    domain: str,
    api_key_info: dict = Depends(verify_api_key),
):
    """
    PUT method not supported. Use PATCH for updates.

    Requires: API key with 'domain:write' or '*' permission
    """
    raise HTTPException(
        status_code=405,
        detail="Method PUT not allowed. Use PATCH for updates.",
        headers={"Allow": "GET, POST, PATCH, DELETE"}
    )


@router.delete("/{domain}", response_model=MessageResponse)
async def delete_domain(
    domain: str,
    force: bool = Query(False, description="Skip deletion preview and force delete"),
    api_key_info: dict = Depends(verify_api_key),
    db: SQLModelManager = Depends(get_db_manager)
):
    """
    Delete domain and all related data (requires authentication).

    Deletes a domain and all its associated data including scans,
    subdomains, alerts, and tool results.

    Requires: API key with 'domain:write' or '*' permission

    Query Parameters:
    - force: Set to true to skip deletion preview and immediately delete
    """
    # Check permission
    if not check_permission(api_key_info, "domain:write"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires 'domain:write' permission."
        )

    service = get_domain_service(db)

    try:
        result = service.delete_domain(domain=domain)

        logger.info(f"Deleted domain via API: {domain} (API key: {api_key_info.get('id')})")

        return MessageResponse(
            message=result['message'],
            details=result.get('deleted')
        )

    except (InvalidDomainFormat, DomainNotFound) as e:
        logger.info(f"Domain not found for deletion: {domain}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting domain {domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete domain")
