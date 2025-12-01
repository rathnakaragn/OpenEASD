"""
Test cases for Domain Service.

Tests domain creation, listing, updating, and deletion operations.
"""

import pytest
import tempfile
from pathlib import Path
from src.services.domain_service import DomainService
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.exceptions import DomainNotFound, DomainAlreadyExists, InvalidDomainFormat
from src.data.models.domain import Domain

@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.sqlite"
        db_manager = SQLModelManager(str(db_path))
        db_manager.initialize()
        yield db_manager
        db_manager.close()

@pytest.fixture
def domain_service(temp_db):
    """Create a DomainService instance with temporary database."""
    return DomainService(temp_db)

class TestDomainServiceCreation:
    """Test cases for domain creation."""

    def test_create_simple_domain(self, domain_service):
        """Test creating a simple domain."""
        domain = domain_service.create_domain('example.com')
        assert isinstance(domain, Domain)
        assert domain.domain == 'example.com'
        assert domain.is_primary is False

    def test_create_primary_domain(self, domain_service):
        """Test creating a primary domain."""
        domain = domain_service.create_domain('example.com', is_primary=True)
        assert domain.is_primary is True

    def test_create_domain_with_email(self, domain_service):
        """Test creating a domain with contact email."""
        email = 'admin@example.com'
        domain = domain_service.create_domain('example.com', contact_email=email)
        assert domain.contact_email == email

    def test_create_domain_with_scan_frequency(self, domain_service):
        """Test creating a domain with scan frequency."""
        domain = domain_service.create_domain('example.com', scan_frequency='daily')
        assert domain.scan_frequency == 'daily'

    def test_create_domain_with_all_metadata(self, domain_service):
        """Test creating a domain with all metadata."""
        domain = domain_service.create_domain(
            domain='example.com',
            is_primary=True,
            contact_email='security@example.com',
            scan_frequency='weekly'
        )
        assert domain.domain == 'example.com'
        assert domain.is_primary is True
        assert domain.contact_email == 'security@example.com'
        assert domain.scan_frequency == 'weekly'

    def test_create_domain_invalid_format_raises_error(self, domain_service):
        """Test that invalid domain format raises error."""
        with pytest.raises(InvalidDomainFormat):
            domain_service.create_domain('invalid..com')

    def test_create_duplicate_domain_raises_error(self, domain_service):
        """Test that creating duplicate domain raises error."""
        domain_service.create_domain('example.com')
        with pytest.raises(DomainAlreadyExists):
            domain_service.create_domain('example.com')

    def test_create_domain_command_injection_rejected(self, domain_service):
        """Test that command injection in domain is rejected."""
        with pytest.raises(InvalidDomainFormat):
            domain_service.create_domain('example.com; rm -rf /')

class TestDomainServiceListing:
    """Test cases for domain listing."""

    def test_list_empty_domains(self, domain_service):
        """Test listing when no domains exist."""                        
        result = domain_service.list_domains()
        assert result['domains'] == []
        assert result['total_count'] == 0
        assert result['has_more'] is False

    def test_list_single_domain(self, domain_service):
        """Test listing with single domain."""
        domain_service.create_domain('example.com')
        result = domain_service.list_domains()
        assert len(result['domains']) == 1
        assert result['domains'][0].domain == 'example.com'
        assert result['total_count'] == 1
        assert result['has_more'] is False

    def test_list_multiple_domains(self, domain_service):
        """Test listing multiple domains."""
        domains = ['example.com', 'test.org', 'api.io']
        for domain in domains:
            domain_service.create_domain(domain)
        result = domain_service.list_domains(limit=20)
        assert len(result['domains']) == 3
        assert result['total_count'] == 3

    def test_list_with_limit(self, domain_service):
        """Test listing with limit."""
        for i in range(5):
            domain_service.create_domain(f'example{i}.com')
        result = domain_service.list_domains(limit=2)
        assert len(result['domains']) == 2
        assert result['has_more'] is True

    def test_list_primary_only(self, domain_service):
        """Test listing only primary domains."""
        domain_service.create_domain('example.com', is_primary=True)
        domain_service.create_domain('test.org', is_primary=False)
        domain_service.create_domain('api.io', is_primary=True)
        result = domain_service.list_domains(primary_only=True)
        assert len(result['domains']) == 2
        for domain in result['domains']:
            assert domain.is_primary is True

class TestDomainServiceRetrieval:
    """Test cases for getting domain details."""

    def test_get_existing_domain(self, domain_service):
        """Test getting details of existing domain."""
        domain_service.create_domain('example.com')
        domain = domain_service.get_domain('example.com')
        assert domain.domain == 'example.com'

    def test_get_nonexistent_domain_raises_error(self, domain_service):
        """Test that getting nonexistent domain raises error."""
        with pytest.raises(DomainNotFound):
            domain_service.get_domain('nonexistent.com')

    def test_get_domain_with_metadata(self, domain_service):
        """Test getting domain with all metadata."""
        domain_service.create_domain(
            'example.com',
            is_primary=True,
            contact_email='admin@example.com',
            scan_frequency='daily'
        )
        domain = domain_service.get_domain('example.com')
        assert domain.is_primary is True
        assert domain.contact_email == 'admin@example.com'
        assert domain.scan_frequency == 'daily'

    def test_get_domain_invalid_format_raises_error(self, domain_service):
        """Test that getting domain with invalid format raises error."""
        with pytest.raises(InvalidDomainFormat):
            domain_service.get_domain('invalid..com')

class TestDomainServiceUpdate:
    """Test cases for domain updates."""

    def test_update_primary_status(self, domain_service):
        """Test updating primary status."""
        domain_service.create_domain('example.com', is_primary=False)
        updated_domain = domain_service.update_domain('example.com', is_primary=True)
        assert updated_domain.is_primary is True

    def test_update_nonexistent_domain_raises_error(self, domain_service):
        """Test that updating nonexistent domain raises error."""
        with pytest.raises(DomainNotFound):
            domain_service.update_domain('nonexistent.com', is_primary=True)

    def test_update_with_no_fields_raises_error(self, domain_service):
        """Test that updating with no fields raises error."""
        domain_service.create_domain('example.com')
        with pytest.raises(ValueError, match="No fields provided"):
            domain_service.update_domain('example.com')

    def test_update_invalid_domain_format_raises_error(self, domain_service):
        """Test that updating domain with invalid format raises error."""
        with pytest.raises(InvalidDomainFormat):
            domain_service.update_domain('invalid..com', is_primary=True)

class TestDomainServiceDeletion:
    """Test cases for domain deletion."""

    def test_delete_existing_domain(self, domain_service):
        """Test deleting an existing domain."""
        domain_service.create_domain('example.com')
        result = domain_service.delete_domain('example.com')
        assert result['success'] is True

    def test_delete_domain_removes_it_from_list(self, domain_service):
        """Test that deleted domain no longer appears in list."""
        domain_service.create_domain('example.com')
        domain_service.delete_domain('example.com')
        result = domain_service.list_domains()
        assert len(result['domains']) == 0

    def test_delete_nonexistent_domain_raises_error(self, domain_service):
        """Test that deleting nonexistent domain raises error."""
        with pytest.raises(DomainNotFound):
            domain_service.delete_domain('nonexistent.com')

    def test_delete_invalid_domain_format_raises_error(self, domain_service):
        """Test that deleting domain with invalid format raises error."""
        with pytest.raises(InvalidDomainFormat):
            domain_service.delete_domain('invalid..com')

class TestDomainServiceIntegration:
    """Integration tests for domain service."""

    def test_create_list_update_delete_workflow(self, domain_service):
        """Test complete CRUD workflow."""
        # Create
        domain_service.create_domain('example.com', is_primary=False)
        # List
        list_result = domain_service.list_domains()
        assert len(list_result['domains']) == 1
        # Get
        domain = domain_service.get_domain('example.com')
        assert domain.domain == 'example.com'
        # Update
        updated_domain = domain_service.update_domain('example.com', is_primary=True)
        assert updated_domain.is_primary is True
        # Delete
        delete_result = domain_service.delete_domain('example.com')
        assert delete_result['success'] is True
        # Verify deletion
        list_after = domain_service.list_domains()
        assert len(list_after['domains']) == 0

    def test_multiple_domains_management(self, domain_service):
        """Test managing multiple domains."""
        domains = [
            ('example.com', True),
            ('api.example.com', False),
            ('cdn.example.com', True),
        ]
        # Create
        for domain, is_primary in domains:
            domain_service.create_domain(domain, is_primary=is_primary)
        # List
        list_result = domain_service.list_domains()
        assert len(list_result['domains']) == 3
        # Filter by primary
        primary_result = domain_service.list_domains(primary_only=True)
        assert len(primary_result['domains']) == 2
        # Update one
        domain_service.update_domain('api.example.com', is_primary=True)
        # Verify
        primary_again = domain_service.list_domains(primary_only=True)
        assert len(primary_again['domains']) == 3
