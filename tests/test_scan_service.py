"""
Test cases for Scan Service.

Tests scan creation, execution, status tracking, and results retrieval.
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.services.scan_service import ScanService
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


@pytest.fixture
def scan_service(temp_db):
    """Create a ScanService instance with temporary database."""
    return ScanService(temp_db)


class TestScanServiceCreation:
    """Test cases for scan session creation."""

    def test_create_scan_single_domain(self, scan_service):
        """Test creating scan session for single domain."""
        result = scan_service.create_scan(['example.com'])

        assert result['success'] is True
        assert result['scan_id'] is not None
        assert len(result['scan_id']) == 36  # UUID format
        assert result['domains'] == ['example.com']
        assert result['scan_type'] == 'passive_subdomain_enum'
        assert result['tool_name'] == 'subfinder'

    def test_create_scan_multiple_domains(self, scan_service):
        """Test creating scan session for multiple domains."""
        domains = ['example.com', 'test.org', 'api.io']
        result = scan_service.create_scan(domains)

        assert result['success'] is True
        assert len(result['scan_id']) == 36
        assert result['domains'] == domains
        assert len(result['domains']) == 3

    def test_create_scan_with_custom_type(self, scan_service):
        """Test creating scan with custom scan type."""
        result = scan_service.create_scan(
            ['example.com'],
            scan_type='active_port_scan'
        )

        assert result['success'] is True
        assert result['scan_type'] == 'active_port_scan'

    def test_create_scan_with_custom_tool(self, scan_service):
        """Test creating scan with custom tool."""
        result = scan_service.create_scan(
            ['example.com'],
            tool_name='amass'
        )

        assert result['success'] is True
        assert result['tool_name'] == 'amass'

    def test_create_scan_invalid_domain_raises_error(self, scan_service):
        """Test that invalid domain raises error."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            scan_service.create_scan(['invalid..com'])

    def test_create_scan_with_invalid_in_list_raises_error(self, scan_service):
        """Test that one invalid domain in list raises error."""
        with pytest.raises(ValueError):
            scan_service.create_scan(['example.com', 'invalid..com', 'test.org'])

    def test_create_scan_validates_all_domains(self, scan_service):
        """Test that all domains are validated."""
        # This should fail on second domain
        with pytest.raises(ValueError):
            scan_service.create_scan([
                'example.com',
                'api.example.com',
                'invalid..com'  # Invalid
            ])


class TestScanServiceExecution:
    """Test cases for scan execution."""

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_execute_scan_successful(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test successful scan execution."""
        # Mock tool outputs
        mock_subfinder.return_value = [
            'api.example.com',
            'cdn.example.com',
            'mail.example.com'
        ]
        mock_dnsx.return_value = [
            {'host': 'api.example.com', 'a': '1.2.3.4'},
            {'host': 'cdn.example.com', 'a': '1.2.3.5'},
            {'host': 'mail.example.com', 'a': '1.2.3.6'}
        ]
        mock_naabu.return_value = [
            {'host': 'api.example.com', 'port': 443, 'protocol': 'tcp'},
            {'host': 'cdn.example.com', 'port': 443, 'protocol': 'tcp'},
            {'host': 'mail.example.com', 'port': 25, 'protocol': 'tcp'}
        ]

        result = scan_service.execute_scan('example.com')

        assert result['success'] is True
        assert result['scan_id'] is not None
        assert result['domain'] == 'example.com'
        assert result['subdomain_count'] == 3
        assert result['active_count'] == 3
        assert result['ports_count'] == 3
        assert result['alerts_count'] == 6  # 3 subdomains + 3 ports

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_execute_scan_no_subdomains(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test scan execution with no subdomains found."""
        mock_subfinder.return_value = []
        mock_dnsx.return_value = []
        mock_naabu.return_value = []

        result = scan_service.execute_scan('example.com')

        assert result['success'] is True
        assert result['subdomain_count'] == 0
        assert result['active_count'] == 0
        assert result['ports_count'] == 0
        assert result['alerts_count'] == 0

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_execute_scan_partial_dns_resolution(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test scan where some subdomains don't resolve."""
        mock_subfinder.return_value = [
            'api.example.com',
            'dead.example.com',  # Won't resolve
            'cdn.example.com'
        ]
        mock_dnsx.return_value = [
            {'host': 'api.example.com', 'a': '1.2.3.4'},
            {'host': 'cdn.example.com', 'a': '1.2.3.5'}
            # dead.example.com not in results
        ]
        mock_naabu.return_value = [
            {'host': 'api.example.com', 'port': 443, 'protocol': 'tcp'},
            {'host': 'cdn.example.com', 'port': 443, 'protocol': 'tcp'}
        ]

        result = scan_service.execute_scan('example.com')

        assert result['subdomain_count'] == 3
        assert result['active_count'] == 2  # Only api and cdn resolved
        assert result['ports_count'] == 2

    @patch('src.services.scan_service.run_subfinder')
    def test_execute_scan_tool_failure(self, mock_subfinder, scan_service):
        """Test scan execution when tool fails."""
        mock_subfinder.side_effect = Exception("Subfinder execution failed")

        with pytest.raises(Exception):
            scan_service.execute_scan('example.com')

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_execute_scan_invalid_domain_raises_error(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test that invalid domain raises error."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            scan_service.execute_scan('invalid..com')

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_execute_scan_creates_domain_if_missing(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test that domain is created if it doesn't exist."""
        mock_subfinder.return_value = ['api.example.com']
        mock_dnsx.return_value = [{'host': 'api.example.com', 'a': '1.2.3.4'}]
        mock_naabu.return_value = []

        result = scan_service.execute_scan('newdomain.com')

        assert result['success'] is True
        # Verify domain was created
        assert scan_service.db.domain_exists('newdomain.com')


class TestScanServiceStatus:
    """Test cases for scan status retrieval."""

    def test_get_scan_status_nonexistent_raises_error(self, scan_service):
        """Test that getting status of nonexistent scan raises error."""
        with pytest.raises(ValueError, match="Scan ID not found"):
            scan_service.get_scan_status('nonexistent-uuid')

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_get_scan_status_after_execution(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test getting status after scan execution."""
        mock_subfinder.return_value = ['api.example.com']
        mock_dnsx.return_value = [{'host': 'api.example.com', 'a': '1.2.3.4'}]
        mock_naabu.return_value = []

        execute_result = scan_service.execute_scan('example.com')
        scan_id = execute_result['scan_id']

        status_result = scan_service.get_scan_status(scan_id)

        assert status_result['success'] is True
        assert status_result['scan'] is not None
        assert status_result['scan']['scan_id'] == scan_id
        assert status_result['scan']['status'] == 'completed'


class TestScanServiceResults:
    """Test cases for scan results retrieval."""

    def test_get_scan_results_nonexistent_raises_error(self, scan_service):
        """Test that getting results of nonexistent scan raises error."""
        with pytest.raises(ValueError, match="Scan ID not found"):
            scan_service.get_scan_results('nonexistent-uuid')

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_get_scan_results_after_execution(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test getting results after scan execution."""
        mock_subfinder.return_value = [
            'api.example.com',
            'cdn.example.com'
        ]
        mock_dnsx.return_value = [
            {'host': 'api.example.com', 'a': '1.2.3.4'},
            {'host': 'cdn.example.com', 'a': '1.2.3.5'}
        ]
        mock_naabu.return_value = [
            {'host': 'api.example.com', 'port': 443, 'protocol': 'tcp'}
        ]

        execute_result = scan_service.execute_scan('example.com')
        scan_id = execute_result['scan_id']

        results = scan_service.get_scan_results(scan_id)

        assert results['success'] is True
        assert results['scan']['scan_id'] == scan_id
        assert results['scan']['domain'] == 'example.com'
        assert results['scan']['status'] == 'completed'
        assert len(results['subdomains']) >= 2
        assert len(results['ports']) >= 1

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_get_scan_results_empty_scan(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test getting results from scan with no findings."""
        mock_subfinder.return_value = []
        mock_dnsx.return_value = []
        mock_naabu.return_value = []

        execute_result = scan_service.execute_scan('example.com')
        scan_id = execute_result['scan_id']

        results = scan_service.get_scan_results(scan_id)

        assert results['success'] is True
        assert len(results['subdomains']) == 0
        assert len(results['ports']) == 0


class TestScanServiceListing:
    """Test cases for scan listing."""

    def test_list_scans_empty(self, scan_service):
        """Test listing when no scans exist."""
        result = scan_service.list_scans()

        assert result['success'] is True
        assert result['scans'] == []
        assert result['total'] == 0

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_list_scans_after_execution(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test listing scans after execution."""
        mock_subfinder.return_value = ['api.example.com']
        mock_dnsx.return_value = [{'host': 'api.example.com', 'a': '1.2.3.4'}]
        mock_naabu.return_value = []

        scan_service.execute_scan('example.com')

        result = scan_service.list_scans()

        assert result['success'] is True
        assert len(result['scans']) == 1
        assert result['total'] == 1
        assert result['scans'][0]['domain'] == 'example.com'
        assert result['scans'][0]['status'] == 'completed'

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_list_scans_with_limit(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test listing scans with limit."""
        mock_subfinder.return_value = []
        mock_dnsx.return_value = []
        mock_naabu.return_value = []

        # Create multiple scans
        for i in range(5):
            scan_service.execute_scan(f'example{i}.com')

        result = scan_service.list_scans(limit=2)

        assert result['total'] == 2  # Limited to 2

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_list_scans_ordered_by_recency(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test that scans are ordered by most recent first."""
        mock_subfinder.return_value = []
        mock_dnsx.return_value = []
        mock_naabu.return_value = []

        # Create multiple scans
        scan_ids = []
        for i in range(3):
            result = scan_service.execute_scan(f'example{i}.com')
            scan_ids.append(result['scan_id'])

        list_result = scan_service.list_scans(limit=10)

        # Most recent should be first
        assert list_result['scans'][0]['scan_id'] == scan_ids[2]


class TestScanServiceIntegration:
    """Integration tests for scan service."""

    @patch('src.services.scan_service.run_subfinder')
    @patch('src.services.scan_service.run_dnsx')
    @patch('src.services.scan_service.run_naabu')
    def test_complete_scan_workflow(self, mock_naabu, mock_dnsx, mock_subfinder, scan_service):
        """Test complete scan workflow from execution to results."""
        mock_subfinder.return_value = ['api.example.com', 'www.example.com']
        mock_dnsx.return_value = [
            {'host': 'api.example.com', 'a': '1.2.3.4'},
            {'host': 'www.example.com', 'a': '1.2.3.5'}
        ]
        mock_naabu.return_value = [
            {'host': 'api.example.com', 'port': 443, 'protocol': 'tcp'},
            {'host': 'www.example.com', 'port': 80, 'protocol': 'tcp'},
            {'host': 'www.example.com', 'port': 443, 'protocol': 'tcp'}
        ]

        # Execute scan
        execute_result = scan_service.execute_scan('example.com')
        scan_id = execute_result['scan_id']

        # Get status
        status_result = scan_service.get_scan_status(scan_id)
        assert status_result['scan']['status'] == 'completed'

        # Get results
        results = scan_service.get_scan_results(scan_id)
        assert len(results['subdomains']) == 2
        assert len(results['ports']) >= 3

        # List scans
        list_result = scan_service.list_scans()
        assert list_result['total'] > 0
        assert any(s['scan_id'] == scan_id for s in list_result['scans'])
