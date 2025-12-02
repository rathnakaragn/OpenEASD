
import pytest
from unittest.mock import MagicMock, patch
from fastapi import Depends

# Since we are running tests from the 'src' directory, we can import directly
from src.api.dependencies import (
    get_db_manager,
    get_domain_service,
    get_scan_service,
    get_alert_service,
    get_findings_service,
)
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.alert_service import AlertService
from src.services.findings_service import FindingsService
from src.data.database.sqlmodel_manager import SQLModelManager

@patch('src.api.dependencies.SQLModelManager')
def test_get_db_manager(mock_sql_manager):
    """Test the database manager dependency."""
    mock_instance = MagicMock()
    mock_sql_manager.return_value = mock_instance

    # The dependency is a generator, so we iterate over it
    db_gen = get_db_manager()
    db = next(db_gen)

    assert db == mock_instance
    mock_instance.initialize.assert_called_once()
    
    # Test that the finally block is called
    with pytest.raises(StopIteration):
        next(db_gen)
    mock_instance.close.assert_called_once()


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

def test_get_alert_service():
    """Test the alert service dependency."""
    mock_db = MagicMock()
    service = get_alert_service(db=mock_db)
    assert service.db == mock_db

def test_get_findings_service():
    """Test the findings service dependency."""
    mock_db = MagicMock()
    service = get_findings_service(db=mock_db)
    assert isinstance(service, FindingsService)
    assert service.db == mock_db
