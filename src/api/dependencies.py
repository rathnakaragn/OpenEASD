"""
Dependency injection for FastAPI routes.

Provides reusable dependencies for database connections,
services, and authentication.
"""

from typing import Generator
from src.data.database.duckdb_manager import DuckDBManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.alert_service import AlertService


def get_db_manager() -> Generator[DuckDBManager, None, None]:
    """
    Dependency to get database manager instance.

    Yields:
        DuckDBManager instance

    Note:
        Automatically handles initialization and cleanup.
    """
    db = DuckDBManager()
    try:
        db.initialize()
        yield db
    finally:
        db.close()


def get_domain_service(db: DuckDBManager = None) -> DomainService:
    """
    Dependency to get domain service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        DomainService instance
    """
    if db is None:
        db = DuckDBManager()
        db.initialize()
    return DomainService(db)


def get_scan_service(db: DuckDBManager = None) -> ScanService:
    """
    Dependency to get scan service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        ScanService instance
    """
    if db is None:
        db = DuckDBManager()
        db.initialize()
    return ScanService(db)


def get_alert_service(db: DuckDBManager = None) -> AlertService:
    """
    Dependency to get alert service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        AlertService instance
    """
    if db is None:
        db = DuckDBManager()
        db.initialize()
    return AlertService(db)
