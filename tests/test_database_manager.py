"""
Test cases for Database Manager (SQLModel).

Tests CRUD operations, filtering, pagination, and data integrity.
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta

from src.data.database.sqlmodel_manager import SQLModelManager


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.sqlite"
        db_manager = SQLModelManager(str(db_path))
        db_manager.initialize()
        yield db_manager
        db_manager.close()


class TestDatabaseInitialization:
    """Test cases for database initialization."""

    def test_database_initializes(self, temp_db):
        """Test that database initializes successfully."""
        assert temp_db is not None
        assert temp_db.engine is not None

    def test_database_creates_file(self):
        """Test that database creates file on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite"
            db = SQLModelManager(str(db_path))
            db.initialize()

            assert db_path.exists()
            db.close()

    def test_database_path_customization(self):
        """Test that database path can be customized."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = Path(tmpdir) / "custom" / "path" / "db.sqlite"
            db = SQLModelManager(str(custom_path))
            db.initialize()

            assert custom_path.exists()
            db.close()


class TestDomainOperations:
    """Test cases for domain CRUD operations."""

    def test_add_domain_basic(self, temp_db):
        """Test adding a basic domain."""
        result = temp_db.add_domain('example.com')

        assert result['success'] is True
        assert result['domain'] == 'example.com'
        assert result['is_primary'] is False

    def test_add_domain_with_all_fields(self, temp_db):
        """Test adding domain with all fields."""
        result = temp_db.add_domain(
            domain='example.com',
            is_primary=True,
            domain_type='apex',
            notes='Test domain',
            tags=['prod', 'critical'],
            contact_email='admin@example.com',
            scan_frequency='daily',
            active_scan_enabled=True
        )

        assert result['success'] is True
        assert result['is_primary'] is True
        assert result['notes'] == 'Test domain'
        assert result['contact_email'] == 'admin@example.com'

    def test_domain_exists_check(self, temp_db):
        """Test domain existence check."""
        assert temp_db.domain_exists('example.com') is False

        temp_db.add_domain('example.com')

        assert temp_db.domain_exists('example.com') is True

    def test_get_domains_empty(self, temp_db):
        """Test getting domains from empty database."""
        result = temp_db.get_domains()

        assert result['total_count'] == 0
        assert result['domains'] == []
        assert result['has_more'] is False

    def test_get_domains_pagination(self, temp_db):
        """Test pagination when getting domains."""
        for i in range(5):
            temp_db.add_domain(f'example{i}.com')

        result = temp_db.get_domains(limit=2, offset=0)

        assert len(result['domains']) == 2
        assert result['total_count'] == 5
        assert result['has_more'] is True

    def test_get_domains_offset(self, temp_db):
        """Test offset parameter in pagination."""
        for i in range(5):
            temp_db.add_domain(f'example{i}.com')

        result1 = temp_db.get_domains(limit=2, offset=0)
        result2 = temp_db.get_domains(limit=2, offset=2)

        # Different domains should be returned
        assert result1['domains'][0]['domain'] != result2['domains'][0]['domain'] or len(result1['domains']) == 0

    def test_get_domains_filter_by_name(self, temp_db):
        """Test filtering domains by name."""
        temp_db.add_domain('example.com')
        temp_db.add_domain('test.org')

        result = temp_db.get_domains(domain_name='example.com')

        assert len(result['domains']) == 1
        assert result['domains'][0]['domain'] == 'example.com'

    def test_get_domains_filter_by_type(self, temp_db):
        """Test filtering domains by type."""
        temp_db.add_domain('example.com', domain_type='apex')
        temp_db.add_domain('sub.example.com', domain_type='subdomain')

        result = temp_db.get_domains(domain_type='apex')

        assert len(result['domains']) >= 1
        for domain in result['domains']:
            assert domain['domain_type'] == 'apex'

    def test_get_domains_primary_only(self, temp_db):
        """Test filtering by primary status."""
        temp_db.add_domain('primary.com', is_primary=True)
        temp_db.add_domain('secondary.com', is_primary=False)

        result = temp_db.get_domains(primary_only=True)

        assert len(result['domains']) >= 1
        for domain in result['domains']:
            assert domain['is_primary'] is True

    def test_update_domain(self, temp_db):
        """Test updating domain fields."""
        temp_db.add_domain('example.com')

        result = temp_db.update_domain(
            'example.com',
            is_primary=True,
            notes='Updated notes'
        )

        assert result['success'] is True
        assert result['domain']['is_primary'] is True
        assert result['domain']['notes'] == 'Updated notes'

    def test_update_domain_tags(self, temp_db):
        """Test updating domain tags."""
        temp_db.add_domain('example.com')

        new_tags = ['new', 'tags']
        result = temp_db.update_domain('example.com', tags=new_tags)

        assert result['success'] is True
        stored_tags = json.loads(result['domain']['tags']) if result['domain']['tags'] else []
        assert stored_tags == new_tags

    def test_delete_domain(self, temp_db):
        """Test deleting a domain."""
        temp_db.add_domain('example.com')
        assert temp_db.domain_exists('example.com')

        result = temp_db.delete_domain('example.com')

        assert result is True
        assert temp_db.domain_exists('example.com') is False

    def test_delete_nonexistent_domain(self, temp_db):
        """Test deleting nonexistent domain returns false."""
        result = temp_db.delete_domain('nonexistent.com')

        assert result is False


class TestScanOperations:
    """Test cases for scan session operations."""

    def test_create_scan_session(self, temp_db):
        """Test creating a scan session."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        assert scan_id is not None
        assert len(scan_id) == 36  # UUID format

    def test_create_scan_multiple_domains(self, temp_db):
        """Test creating scan with multiple domains."""
        domains = ['example.com', 'test.org']
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=domains
        )

        assert scan_id is not None

    def test_create_scan_with_tool(self, temp_db):
        """Test creating scan with tool name."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com'],
            tool_name='subfinder'
        )

        assert scan_id is not None

    def test_get_scan_status(self, temp_db):
        """Test getting scan status."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        status = temp_db.get_scan_status(scan_id)

        assert status is not None
        assert status['scan_id'] == scan_id
        assert status['status'] == 'running'

    def test_update_scan_status(self, temp_db):
        """Test updating scan status."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        result = temp_db.update_scan_status(
            scan_id,
            'completed',
            findings_count=5
        )

        assert result['success'] is True

        # Verify update
        status = temp_db.get_scan_status(scan_id)
        assert status['status'] == 'completed'
        assert status['findings_count'] == 5

    def test_update_scan_with_timestamps(self, temp_db):
        """Test updating scan with timestamp."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        from src.utils.timezone import get_ist_now
        now = get_ist_now()

        result = temp_db.update_scan_status(
            scan_id,
            'completed',
            end_time=now
        )

        assert result['success'] is True

    def test_scan_status_nonexistent(self, temp_db):
        """Test getting status of nonexistent scan."""
        status = temp_db.get_scan_status('nonexistent-uuid')

        assert status is None


class TestAlertOperations:
    """Test cases for alert operations."""

    def test_store_alerts(self, temp_db):
        """Test storing alerts."""
        from src.utils.timezone import get_ist_now

        alerts = [
            {
                'scan_id': 'test-scan-1',
                'domain': 'api.example.com',
                'vulnerability_type': 'subdomain_discovered',
                'severity': 'info',
                'description': 'New subdomain found',
                'tool_source': 'subfinder',
                'discovered_at': get_ist_now()
            }
        ]

        result = temp_db.store_alerts(alerts)

        assert result['success'] is True

    def test_get_alerts(self, temp_db):
        """Test retrieving alerts."""
        from src.utils.timezone import get_ist_now

        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        alerts = [
            {
                'scan_id': scan_id,
                'domain': 'api.example.com',
                'vulnerability_type': 'subdomain_discovered',
                'severity': 'info',
                'description': 'Subdomain found',
                'tool_source': 'subfinder',
                'discovered_at': get_ist_now()
            }
        ]

        temp_db.store_alerts(alerts)

        result = temp_db.get_alerts(limit=10)

        assert result['total_count'] >= 1
        assert len(result['alerts']) >= 1

    def test_get_alerts_filter_by_severity(self, temp_db):
        """Test filtering alerts by severity."""
        from src.utils.timezone import get_ist_now

        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        alerts = [
            {
                'scan_id': scan_id,
                'domain': 'api.example.com',
                'vulnerability_type': 'critical_vuln',
                'severity': 'critical',
                'description': 'Critical finding',
                'tool_source': 'test',
                'discovered_at': get_ist_now()
            },
            {
                'scan_id': scan_id,
                'domain': 'api.example.com',
                'vulnerability_type': 'info',
                'severity': 'info',
                'description': 'Info',
                'tool_source': 'test',
                'discovered_at': get_ist_now()
            }
        ]

        temp_db.store_alerts(alerts)

        result = temp_db.get_alerts(severity='critical')

        assert len(result['alerts']) >= 1


class TestSubdomainHistory:
    """Test cases for subdomain history operations."""

    def test_store_subdomain_history(self, temp_db):
        """Test storing subdomain history."""
        from src.utils.timezone import get_ist_now

        scan_id = 'test-scan-1'
        result = temp_db.store_subdomain_history(
            scan_id=scan_id,
            apex_domain='example.com',
            subdomain='api.example.com',
            status='new',
            tool_source='subfinder'
        )

        assert result['success'] is True

    def test_get_subdomain_history(self, temp_db):
        """Test retrieving subdomain history."""
        from src.utils.timezone import get_ist_now

        scan_id = 'test-scan-1'
        temp_db.store_subdomain_history(
            scan_id=scan_id,
            apex_domain='example.com',
            subdomain='api.example.com',
            status='new',
            tool_source='subfinder'
        )

        result = temp_db.get_subdomain_history('example.com', limit=10)

        assert result['total_count'] >= 1
        assert len(result['history']) >= 1

    def test_get_subdomain_history_pagination(self, temp_db):
        """Test pagination of subdomain history."""
        scan_id = 'test-scan-1'
        for i in range(5):
            temp_db.store_subdomain_history(
                scan_id=scan_id,
                apex_domain='example.com',
                subdomain=f'sub{i}.example.com',
                status='new',
                tool_source='subfinder'
            )

        result = temp_db.get_subdomain_history('example.com', limit=2)

        assert len(result['history']) <= 2
        assert result['total_count'] >= 2


class TestDatabaseTransactionIntegrity:
    """Test cases for transaction integrity and consistency."""

    def test_multiple_operations_consistency(self, temp_db):
        """Test that multiple operations maintain consistency."""
        # Create domain
        temp_db.add_domain('example.com')

        # Create scan
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        # Store alert
        from src.utils.timezone import get_ist_now
        temp_db.store_alerts([{
            'scan_id': scan_id,
            'domain': 'api.example.com',
            'vulnerability_type': 'subdomain_discovered',
            'severity': 'info',
            'description': 'Found',
            'tool_source': 'subfinder',
            'discovered_at': get_ist_now()
        }])

        # Verify all data exists
        assert temp_db.domain_exists('example.com')
        assert temp_db.get_scan_status(scan_id) is not None
        assert temp_db.get_alerts()['total_count'] >= 1

    def test_database_handles_concurrent_operations(self, temp_db):
        """Test that database handles multiple operations gracefully."""
        domains = [f'example{i}.com' for i in range(10)]

        for domain in domains:
            temp_db.add_domain(domain)

        result = temp_db.get_domains(limit=20)

        assert result['total_count'] >= 10


class TestDatabaseEdgeCases:
    """Test cases for edge cases and boundary conditions."""

    def test_very_long_domain_name(self, temp_db):
        """Test handling of maximum length domain."""
        long_domain = 'a' * 63 + '.com'  # 67 chars total
        result = temp_db.add_domain(long_domain)

        assert result['success'] is True

    def test_special_characters_in_notes(self, temp_db):
        """Test handling special characters in notes."""
        special_notes = "Test with 'quotes' and \"double\" quotes & symbols!"
        result = temp_db.add_domain('example.com', notes=special_notes)

        assert result['success'] is True
        assert result['notes'] == special_notes

    def test_unicode_in_notes(self, temp_db):
        """Test handling unicode in notes."""
        unicode_notes = "Test with émojis 🔒 and spëcial chars"
        result = temp_db.add_domain('example.com', notes=unicode_notes)

        assert result['success'] is True

    def test_empty_tags_list(self, temp_db):
        """Test handling empty tags list."""
        result = temp_db.add_domain('example.com', tags=[])

        assert result['success'] is True

    def test_large_tags_list(self, temp_db):
        """Test handling large tags list."""
        large_tags = [f'tag{i}' for i in range(100)]
        result = temp_db.add_domain('example.com', tags=large_tags)

        assert result['success'] is True
