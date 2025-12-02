"""
Dependency injection for FastAPI routes.

Provides reusable dependencies for database connections and services.
API is read-only - no authentication required.
"""

from typing import Generator
from fastapi import Depends
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.findings_service import FindingsService


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


def get_findings_service(db: SQLModelManager = Depends(get_db_manager)) -> FindingsService:
    """
    Dependency to get findings service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        FindingsService instance
    """
    return FindingsService(db)
