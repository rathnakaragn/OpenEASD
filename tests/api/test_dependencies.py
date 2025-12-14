
import pytest
from unittest.mock import MagicMock, patch
from fastapi import Depends

# Since we are running tests from the 'src' directory, we can import directly
from src.api.dependencies import (
    get_db_manager,
    get_domain_service,
    get_scan_service,
    get_findings_service,
)
import src.api.dependencies as deps
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.findings_service import FindingsService
from src.data.database.sqlmodel_manager import SQLModelManager

def test_get_db_manager():
    """Test the database manager dependency returns singleton."""
    # Reset the singleton for testing
    deps._db_manager = None
    deps._db_initialized = False

    # First call should create instance
    db1 = get_db_manager()
    assert isinstance(db1, SQLModelManager)

    # Second call should return same instance (singleton)
    db2 = get_db_manager()
    assert db1 is db2

    # Reset for other tests
    deps._db_manager = None
    deps._db_initialized = False


def test_get_domain_service():
    """Test the domain service dependency."""
    mock_db = MagicMock()
    # We need to manually call the dependency with the mock
    service = get_domain_service(db=mock_db)
    assert isinstance(service, DomainService)
    assert service.db == mock_db

def test_get_scan_service():
    """Test the scan service dependency."""
    mock_db = MagicMock()
    service = get_scan_service(db=mock_db)
    assert isinstance(service, ScanService)
    assert service.db == mock_db

def test_get_findings_service():
    """Test the findings service dependency."""
    mock_db = MagicMock()
    service = get_findings_service(db=mock_db)
    assert isinstance(service, FindingsService)
    assert service.db == mock_db
