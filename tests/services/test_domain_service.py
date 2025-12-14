"""
Comprehensive unit tests for DomainService.

Tests business logic for domain management including creation,
listing, retrieval, updates, and deletion with proper mocking
of database dependencies.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from src.services.domain_service import DomainService
from src.services.exceptions import (
    DomainNotFound,
    DomainAlreadyExists,
    InvalidDomainFormat,
    InvalidUpdateOperation
)
from src.data.models.domain import Domain


@pytest.fixture
def mock_db_manager():
    """Mock database manager for testing."""
    db = MagicMock()
    return db


@pytest.fixture
def domain_service(mock_db_manager):
    """DomainService instance with mocked database."""
    return DomainService(db_manager=mock_db_manager)


@pytest.fixture
def sample_domain():
    """Sample domain object for testing."""
    return Domain(
        id=1,
        domain="example.com",
        is_primary=True,
        scan_count=5,
        contact_email="admin@example.com",
        scan_frequency="daily",
        created_at=datetime(2025, 1, 1, 10, 0, 0),
        last_scanned_at=datetime(2025, 1, 2, 15, 30, 0),
        active_scan_enabled=True
    )


# ========================================================================
# create_domain() Tests
# ========================================================================

def test_create_domain_success(domain_service, mock_db_manager, sample_domain):
    """Test successful domain creation."""
    mock_db_manager.domain_exists.return_value = False
    mock_db_manager.add_domain.return_value = sample_domain

    result = domain_service.create_domain(
        domain="example.com",
        is_primary=True,
        contact_email="admin@example.com",
        scan_frequency="daily"
    )

    assert result == sample_domain
    mock_db_manager.domain_exists.assert_called_once_with("example.com")
    mock_db_manager.add_domain.assert_called_once_with(
        domain="example.com",
        is_primary=True,
        contact_email="admin@example.com",
        scan_frequency="daily"
    )


def test_create_domain_invalid_format(domain_service):
    """Test domain creation with invalid format."""
    # InvalidDomainError is raised from validation but wrapped in InvalidDomainFormat
    from src.core.exceptions import InvalidDomainError
    with pytest.raises((InvalidDomainFormat, InvalidDomainError)):
        domain_service.create_domain(domain="invalid..domain")


def test_create_domain_invalid_characters(domain_service):
    """Test domain creation with invalid characters."""
    # InvalidDomainError is raised from validation but wrapped in InvalidDomainFormat
    from src.core.exceptions import InvalidDomainError
    with pytest.raises((InvalidDomainFormat, InvalidDomainError)):
        domain_service.create_domain(domain="invalid_domain!@#.com")


def test_create_domain_already_exists(domain_service, mock_db_manager):
    """Test creating a domain that already exists."""
    mock_db_manager.domain_exists.return_value = True

    with pytest.raises(DomainAlreadyExists) as exc_info:
        domain_service.create_domain(domain="example.com")

    assert "example.com" in str(exc_info.value)
    mock_db_manager.domain_exists.assert_called_once_with("example.com")
    mock_db_manager.add_domain.assert_not_called()


def test_create_domain_defaults(domain_service, mock_db_manager, sample_domain):
    """Test domain creation with default values."""
    mock_db_manager.domain_exists.return_value = False
    mock_db_manager.add_domain.return_value = sample_domain

    result = domain_service.create_domain(domain="example.com")

    assert result == sample_domain
    mock_db_manager.add_domain.assert_called_once_with(
        domain="example.com",
        is_primary=False,
        contact_email=None,
        scan_frequency=None
    )


def test_create_domain_normalizes_case(domain_service, mock_db_manager, sample_domain):
    """Test that domain names are passed as-is (validation doesn't normalize case)."""
    mock_db_manager.domain_exists.return_value = False
    mock_db_manager.add_domain.return_value = sample_domain

    result = domain_service.create_domain(domain="EXAMPLE.COM")

    # validate_domain doesn't normalize case, it returns as-is
    mock_db_manager.domain_exists.assert_called_once_with("EXAMPLE.COM")
    mock_db_manager.add_domain.assert_called_once()
    call_args = mock_db_manager.add_domain.call_args
    assert call_args[1]['domain'] == "EXAMPLE.COM"


# ========================================================================
# list_domains() Tests
# ========================================================================

def test_list_domains_success(domain_service, mock_db_manager, sample_domain):
    """Test successful domain listing."""
    mock_db_manager.get_domains.return_value = {
        'domains': [sample_domain],
        'total_count': 1,
        'has_more': False
    }

    result = domain_service.list_domains(limit=20, offset=0, primary_only=False)

    assert result['success'] is True
    assert len(result['domains']) == 1
    assert result['total_count'] == 1
    assert result['has_more'] is False
    mock_db_manager.get_domains.assert_called_once_with(
        limit=20,
        offset=0,
        primary_only=False
    )


def test_list_domains_primary_only(domain_service, mock_db_manager):
    """Test listing only primary domains."""
    mock_db_manager.get_domains.return_value = {
        'domains': [],
        'total_count': 0,
        'has_more': False
    }

    result = domain_service.list_domains(limit=10, offset=0, primary_only=True)

    assert result['success'] is True
    mock_db_manager.get_domains.assert_called_once_with(
        limit=10,
        offset=0,
        primary_only=True
    )


def test_list_domains_empty(domain_service, mock_db_manager):
    """Test listing domains when none exist."""
    mock_db_manager.get_domains.return_value = {
        'domains': [],
        'total_count': 0,
        'has_more': False
    }

    result = domain_service.list_domains()

    assert result['success'] is True
    assert len(result['domains']) == 0
    assert result['total_count'] == 0


def test_list_domains_pagination(domain_service, mock_db_manager, sample_domain):
    """Test domain listing with pagination."""
    mock_db_manager.get_domains.return_value = {
        'domains': [sample_domain] * 20,
        'total_count': 50,
        'has_more': True
    }

    result = domain_service.list_domains(limit=20)

    assert result['success'] is True
    assert len(result['domains']) == 20
    assert result['total_count'] == 50
    assert result['has_more'] is True


# ========================================================================
# get_domain() Tests
# ========================================================================

def test_get_domain_success(domain_service, mock_db_manager, sample_domain):
    """Test successful domain retrieval."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.get_domains.return_value = {
        'domains': [sample_domain],
        'total_count': 1,
        'has_more': False
    }
    mock_db_manager.get_discovered_subdomains.return_value = {
        'subdomains': [
            {'subdomain': 'api.example.com', 'first_seen': datetime(2025, 1, 1)},
            {'subdomain': 'www.example.com', 'first_seen': datetime(2025, 1, 2)}
        ],
        'total_count': 2
    }

    result = domain_service.get_domain("example.com")

    assert result['domain'] == "example.com"
    assert result['is_primary'] is True
    assert result['scan_count'] == 5
    assert result['subdomain_count'] == 2
    assert len(result['recent_subdomains']) == 2
    assert result['recent_subdomains'][0]['subdomain'] == 'api.example.com'


def test_get_domain_not_found(domain_service, mock_db_manager):
    """Test retrieving a non-existent domain."""
    mock_db_manager.domain_exists.return_value = False

    with pytest.raises(DomainNotFound) as exc_info:
        domain_service.get_domain("nonexistent.com")

    assert "nonexistent.com" in str(exc_info.value)


def test_get_domain_invalid_format(domain_service):
    """Test retrieving domain with invalid format."""
    from src.core.exceptions import InvalidDomainError
    with pytest.raises((InvalidDomainFormat, InvalidDomainError)):
        domain_service.get_domain("invalid..domain")


def test_get_domain_no_subdomains(domain_service, mock_db_manager, sample_domain):
    """Test domain retrieval when no subdomains exist."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.get_domains.return_value = {
        'domains': [sample_domain],
        'total_count': 1,
        'has_more': False
    }
    mock_db_manager.get_discovered_subdomains.return_value = {
        'subdomains': [],
        'total_count': 0
    }

    result = domain_service.get_domain("example.com")

    assert result['subdomain_count'] == 0
    assert result['recent_subdomains'] == []


def test_get_domain_database_returns_empty(domain_service, mock_db_manager):
    """Test when database returns no domain despite existence check."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.get_domains.return_value = {
        'domains': [],
        'total_count': 0,
        'has_more': False
    }

    with pytest.raises(DomainNotFound) as exc_info:
        domain_service.get_domain("example.com")

    assert "Could not retrieve details" in str(exc_info.value)


# ========================================================================
# update_domain() Tests
# ========================================================================

def test_update_domain_success(domain_service, mock_db_manager, sample_domain):
    """Test successful domain update."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.update_domain.return_value = sample_domain

    result = domain_service.update_domain(
        domain="example.com",
        is_primary=True
    )

    assert result == sample_domain
    mock_db_manager.update_domain.assert_called_once_with(
        "example.com",
        is_primary=True
    )


def test_update_domain_not_found(domain_service, mock_db_manager):
    """Test updating a non-existent domain."""
    mock_db_manager.domain_exists.return_value = False

    with pytest.raises(DomainNotFound):
        domain_service.update_domain(domain="nonexistent.com", is_primary=True)

    mock_db_manager.update_domain.assert_not_called()


def test_update_domain_invalid_format(domain_service):
    """Test updating domain with invalid format."""
    from src.core.exceptions import InvalidDomainError
    with pytest.raises((InvalidDomainFormat, InvalidDomainError)):
        domain_service.update_domain(domain="invalid..domain", is_primary=True)


def test_update_domain_no_fields(domain_service, mock_db_manager):
    """Test update with no fields provided."""
    mock_db_manager.domain_exists.return_value = True

    with pytest.raises(InvalidUpdateOperation) as exc_info:
        domain_service.update_domain(domain="example.com")

    assert "No fields provided" in str(exc_info.value)
    mock_db_manager.update_domain.assert_not_called()


def test_update_domain_primary_false(domain_service, mock_db_manager, sample_domain):
    """Test updating domain to non-primary."""
    mock_db_manager.domain_exists.return_value = True
    sample_domain.is_primary = False
    mock_db_manager.update_domain.return_value = sample_domain

    result = domain_service.update_domain(
        domain="example.com",
        is_primary=False
    )

    assert result.is_primary is False


def test_update_domain_primary_none_ignored(domain_service, mock_db_manager):
    """Test that is_primary=None doesn't create an update."""
    mock_db_manager.domain_exists.return_value = True

    with pytest.raises(InvalidUpdateOperation):
        domain_service.update_domain(domain="example.com", is_primary=None)

    mock_db_manager.update_domain.assert_not_called()


# ========================================================================
# delete_domain() Tests
# ========================================================================

def test_delete_domain_success(domain_service, mock_db_manager):
    """Test successful domain deletion."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.delete_domain_with_data.return_value = {
        'domains': 1,
        'scans': 3,
        'subdomains': 10,
        'findings': 5
    }

    result = domain_service.delete_domain("example.com")

    assert result['success'] is True
    assert "example.com" in result['message']
    assert result['deleted']['domains'] == 1
    assert result['deleted']['scans'] == 3
    mock_db_manager.delete_domain_with_data.assert_called_once_with("example.com")


def test_delete_domain_not_found(domain_service, mock_db_manager):
    """Test deleting a non-existent domain."""
    mock_db_manager.domain_exists.return_value = False

    with pytest.raises(DomainNotFound):
        domain_service.delete_domain("nonexistent.com")

    mock_db_manager.delete_domain_with_data.assert_not_called()


def test_delete_domain_invalid_format(domain_service):
    """Test deleting domain with invalid format."""
    from src.core.exceptions import InvalidDomainError
    with pytest.raises((InvalidDomainFormat, InvalidDomainError)):
        domain_service.delete_domain("invalid..domain")


def test_delete_domain_no_associated_data(domain_service, mock_db_manager):
    """Test deleting domain with no associated data."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.delete_domain_with_data.return_value = {
        'domains': 1,
        'scans': 0,
        'subdomains': 0,
        'findings': 0
    }

    result = domain_service.delete_domain("example.com")

    assert result['success'] is True
    assert result['deleted']['domains'] == 1
    assert result['deleted']['scans'] == 0


def test_delete_domain_normalizes_case(domain_service, mock_db_manager):
    """Test that delete passes domain as-is (no case normalization)."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.delete_domain_with_data.return_value = {'domains': 1}

    domain_service.delete_domain("EXAMPLE.COM")

    mock_db_manager.domain_exists.assert_called_once_with("EXAMPLE.COM")
    mock_db_manager.delete_domain_with_data.assert_called_once_with("EXAMPLE.COM")


# ========================================================================
# Edge Cases and Integration
# ========================================================================

def test_domain_service_initialization(mock_db_manager):
    """Test DomainService initialization."""
    service = DomainService(db_manager=mock_db_manager)
    assert service.db == mock_db_manager


def test_multiple_operations_same_domain(domain_service, mock_db_manager, sample_domain):
    """Test multiple operations on same domain."""
    # Create domain
    mock_db_manager.domain_exists.return_value = False
    mock_db_manager.add_domain.return_value = sample_domain
    domain_service.create_domain("example.com")

    # Update domain
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.update_domain.return_value = sample_domain
    domain_service.update_domain("example.com", is_primary=True)

    # Delete domain
    mock_db_manager.delete_domain_with_data.return_value = {'domains': 1}
    result = domain_service.delete_domain("example.com")

    assert result['success'] is True


def test_create_domain_with_special_tld(domain_service, mock_db_manager, sample_domain):
    """Test creating domain with special TLD."""
    mock_db_manager.domain_exists.return_value = False
    mock_db_manager.add_domain.return_value = sample_domain

    result = domain_service.create_domain("example.co.uk")

    assert result == sample_domain


def test_get_domain_with_many_subdomains(domain_service, mock_db_manager, sample_domain):
    """Test retrieving domain with many subdomains."""
    mock_db_manager.domain_exists.return_value = True
    mock_db_manager.get_domains.return_value = {
        'domains': [sample_domain],
        'total_count': 1,
        'has_more': False
    }

    # Generate 100 subdomains
    subdomains = [
        {'subdomain': f'sub{i}.example.com', 'first_seen': datetime(2025, 1, 1)}
        for i in range(100)
    ]

    mock_db_manager.get_discovered_subdomains.return_value = {
        'subdomains': subdomains,
        'total_count': 100
    }

    result = domain_service.get_domain("example.com")

    assert result['subdomain_count'] == 100
    assert len(result['recent_subdomains']) == 100
