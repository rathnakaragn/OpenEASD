"""
Dependency injection for FastAPI routes.

Provides reusable dependencies for database connections,
services, and authentication.
"""

import hashlib
from typing import Generator, Optional
from fastapi import Depends, HTTPException, Header
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.alert_service import AlertService


def get_db_manager() -> Generator[SQLModelManager, None, None]:
    """
    Dependency to get database manager instance.

    Yields:
        SQLModelManager instance

    Note:
        Automatically handles initialization and cleanup.
    """
    db = SQLModelManager()
    try:
        db.initialize()
        yield db
    finally:
        db.close()


def get_domain_service(db: SQLModelManager = Depends(get_db_manager)) -> DomainService:
    """
    Dependency to get domain service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        DomainService instance
    """
    return DomainService(db)


def get_scan_service(db: SQLModelManager = Depends(get_db_manager)) -> ScanService:
    """
    Dependency to get scan service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        ScanService instance
    """
    return ScanService(db)


def get_alert_service(db: SQLModelManager = Depends(get_db_manager)) -> AlertService:
    """
    Dependency to get alert service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        AlertService instance
    """
    return AlertService(db)


def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: SQLModelManager = Depends(get_db_manager)
) -> dict:
    """
    Dependency to verify API key authentication.

    Args:
        x_api_key: API key from X-API-Key header
        db: Database manager (injected by FastAPI)

    Returns:
        API key information dict

    Raises:
        HTTPException: If API key is invalid or missing
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Hash the provided key
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    # Verify against database (include inactive to check for revoked keys)
    api_key_info = db.get_api_key_by_hash(key_hash, include_inactive=True)

    if not api_key_info:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Check if key is active
    if not api_key_info.get('is_active', False):
        raise HTTPException(
            status_code=401,
            detail="API key has been revoked",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Check expiration if set
    if api_key_info.get('expires_at'):
        from datetime import datetime
        if datetime.utcnow() > api_key_info['expires_at']:
            raise HTTPException(
                status_code=401,
                detail="API key has expired",
                headers={"WWW-Authenticate": "ApiKey"}
            )

    return api_key_info


def check_permission(api_key_info: dict, required_permission: str) -> bool:
    """
    Check if API key has required permission.

    Args:
        api_key_info: API key information dict from verify_api_key
        required_permission: Required permission (e.g., "domain:write", "scan:execute")

    Returns:
        True if has permission, False otherwise
    """
    permissions = api_key_info.get('permissions', [])
    return required_permission in permissions or '*' in permissions
