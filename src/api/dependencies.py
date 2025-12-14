"""
Dependency injection for FastAPI routes.

Provides reusable dependencies for database connections and services.
"""

import threading
from typing import Generator, Optional
from fastapi import Depends
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.findings_service import FindingsService
from src.messaging.job_queue import JobQueue, get_job_queue as _get_job_queue


# Singleton database manager instance with thread-safe initialization
_db_manager: Optional[SQLModelManager] = None
_db_initialized: bool = False
_db_lock = threading.Lock()


def get_db_manager() -> SQLModelManager:
    """
    Dependency to get database manager singleton instance.

    Returns:
        SQLModelManager instance

    Note:
        Uses double-checked locking pattern for thread-safe singleton initialization.
        This ensures only one instance is created even under concurrent requests.
    """
    global _db_manager, _db_initialized

    # Fast path: if already initialized, return immediately
    if _db_manager is not None and _db_initialized:
        return _db_manager

    # Slow path: acquire lock and initialize
    with _db_lock:
        # Double-check after acquiring lock
        if _db_manager is None:
            _db_manager = SQLModelManager()

        if not _db_initialized:
            _db_manager.initialize()
            _db_initialized = True

    return _db_manager


def cleanup_db_manager() -> None:
    """
    Cleanup database manager on shutdown.

    Called during application shutdown to properly close database connections.
    """
    global _db_manager, _db_initialized

    with _db_lock:
        if _db_manager is not None:
            _db_manager.close()
            _db_manager = None
            _db_initialized = False


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


def get_job_queue(db: SQLModelManager = Depends(get_db_manager)) -> JobQueue:
    """
    Dependency to get job queue instance with database persistence.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        JobQueue instance with db_manager for job persistence
    """
    return _get_job_queue(db_manager=db)
