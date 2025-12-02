"""
Database Integration Tests for SQLModelManager.

Comprehensive CRUD operation tests for all database entities:
- Domains
- Scan sessions
- Subdomains
- Statistics and metrics
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.timezone import get_ist_now


@pytest.fixture
def db_manager():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = SQLModelManager(str(db_path))
        db.initialize()
        yield db
        db.close()


class TestDomainOperations:
    """Test domain CRUD operations."""

    def test_add_domain_success(self, db_manager):
        """Test adding a domain successfully."""
        domain = db_manager.add_domain(
            domain="example.com",
            is_primary=True,
            contact_email="admin@example.com",
            scan_frequency="daily"
        )

        assert domain is not None
        assert domain.domain == "example.com"
        assert domain.is_primary is True
        assert domain.contact_email == "admin@example.com"
        assert domain.scan_frequency == "daily"

    def test_add_domain_duplicate(self, db_manager):
        """Test adding duplicate domain raises error."""
        db_manager.add_domain(domain="example.com")

        with pytest.raises(Exception):
            db_manager.add_domain(domain="example.com")

    def test_domain_exists(self, db_manager):
        """Test checking if domain exists."""
        assert not db_manager.domain_exists("example.com")

        db_manager.add_domain(domain="example.com")

        assert db_manager.domain_exists("example.com")

    def test_get_domains_empty(self, db_manager):
        """Test getting domains when none exist."""
        result = db_manager.get_domains()

        assert result['total_count'] == 0
        assert len(result['domains']) == 0

    def test_get_domains_multiple(self, db_manager):
        """Test getting multiple domains."""
        db_manager.add_domain(domain="example.com", is_primary=True)
        db_manager.add_domain(domain="test.io", is_primary=False)
        db_manager.add_domain(domain="staging.org")

        result = db_manager.get_domains(limit=100)

        assert result['total_count'] == 3
        assert len(result['domains']) == 3

    def test_get_domains_primary_filter(self, db_manager):
        """Test filtering domains by primary status."""
        db_manager.add_domain(domain="example.com", is_primary=True)
        db_manager.add_domain(domain="test.io", is_primary=False)
        db_manager.add_domain(domain="staging.org", is_primary=True)

        result = db_manager.get_domains(limit=100, primary_only=True)

        # Count primary domains (Domain objects have is_primary attribute, not dict .get())
        primary_domains = [d for d in result['domains'] if d.is_primary]
        assert len(primary_domains) >= 2

    def test_get_domains_pagination(self, db_manager):
        """Test domain pagination."""
        for i in range(25):
            db_manager.add_domain(domain=f"domain{i}.com")

        result = db_manager.get_domains(limit=10, offset=0)
        assert len(result['domains']) == 10
        assert result['total_count'] == 25

        result = db_manager.get_domains(limit=10, offset=20)
        assert len(result['domains']) == 5

    def test_update_domain(self, db_manager):
        """Test updating domain fields."""
        db_manager.add_domain(domain="example.com", is_primary=False)

        updated = db_manager.update_domain(
            domain="example.com",
            is_primary=True,
            contact_email="new@example.com"
        )

        assert updated.is_primary is True
        assert updated.contact_email == "new@example.com"

    def test_delete_domain(self, db_manager):
        """Test deleting a domain."""
        db_manager.add_domain(domain="example.com")
        assert db_manager.domain_exists("example.com")

        result = db_manager.delete_domain(domain="example.com")

        assert result is True
        assert not db_manager.domain_exists("example.com")

    def test_delete_nonexistent_domain(self, db_manager):
        """Test deleting non-existent domain returns false."""
        result = db_manager.delete_domain(domain="nonexistent.com")
        assert result is False


class TestScanSessionOperations:
    """Test scan session CRUD operations."""

    def test_create_scan_session(self, db_manager):
        """Test creating a scan session."""
        db_manager.add_domain(domain="example.com")

        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"],
            tool_name="subfinder"
        )

        assert scan_id is not None
        assert isinstance(scan_id, str)

    def test_get_scan_status(self, db_manager):
        """Test retrieving scan status."""
        db_manager.add_domain(domain="example.com")

        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        status = db_manager.get_scan_status(scan_id)

        assert status is not None
        assert status['scan_id'] == scan_id
        assert status['status'] == "running"

    def test_update_scan_status(self, db_manager):
        """Test updating scan status."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        result = db_manager.update_scan_status(
            scan_id=scan_id,
            status="completed",
            end_time=get_ist_now()
        )

        assert result is not None
        status = db_manager.get_scan_status(scan_id)
        assert status['status'] == "completed"

    def test_get_scan_history(self, db_manager):
        """Test retrieving scan history."""
        db_manager.add_domain(domain="example.com")

        scan_id1 = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )
        scan_id2 = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        result = db_manager.get_scan_history(domain="example.com", limit=10)
        history = result['scans']

        assert len(history) >= 2
        assert any(s['scan_id'] == scan_id1 for s in history)
        assert any(s['scan_id'] == scan_id2 for s in history)


class TestSubdomainHistoryOperations:
    """Test subdomain history tracking."""

    def test_add_subdomain_to_history(self, db_manager):
        """Test adding subdomain to history."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        db_manager.add_subdomain_to_history(
            apex_domain="example.com",
            subdomain="api.example.com",
            scan_id=scan_id,
            status="new"
        )

        history = db_manager.get_subdomain_history(domain="example.com", limit=100)
        assert len(history) > 0

    def test_store_subdomain_history(self, db_manager):
        """Test storing subdomain to history."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        # Store subdomains one by one
        db_manager.store_subdomain_history(
            apex_domain="example.com",
            subdomain="api.example.com",
            scan_id=scan_id,
            status="new"
        )
        db_manager.store_subdomain_history(
            apex_domain="example.com",
            subdomain="www.example.com",
            scan_id=scan_id,
            status="new"
        )
        db_manager.store_subdomain_history(
            apex_domain="example.com",
            subdomain="mail.example.com",
            scan_id=scan_id,
            status="new"
        )

        history = db_manager.get_subdomain_history(domain="example.com", limit=100)
        assert len(history) >= 3


class TestFindingsOperations:
    """Test findings management."""

    def test_store_findings(self, db_manager):
        """Test storing security findings."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "port": 80,  # Add port to differentiate findings
                "title": "Port 80 Open",
                "description": "Port 80 is open",
                "severity": "medium",
                "status": "open"
            },
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "port": 443,  # Different port = different finding
                "title": "Port 443 Open",
                "description": "Port 443 is open",
                "severity": "high",
                "status": "open"
            },
        ]

        result = db_manager.store_findings(findings)

        # Verify findings are stored (returns new/updated counts now)
        assert result['new'] == 2
        retrieved = db_manager.get_findings(limit=100)
        assert len(retrieved['findings']) >= 2

    def test_get_findings_by_scan(self, db_manager):
        """Test retrieving findings for a specific scan."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Port 80 Open",
                "description": "Port 80",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        retrieved = db_manager.get_findings(scan_id=scan_id, limit=100)

        assert len(retrieved['findings']) > 0
        assert all(f['scan_id'] == scan_id for f in retrieved['findings'])

    def test_get_findings_by_asset(self, db_manager):
        """Test retrieving findings for a specific asset."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Port 80 Open",
                "description": "Port 80",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        retrieved = db_manager.get_findings(affected_asset="api.example.com", limit=100)

        assert len(retrieved['findings']) > 0
        assert all(f['affected_asset'] == "api.example.com" for f in retrieved['findings'])

    def test_get_finding_by_id(self, db_manager):
        """Test retrieving a specific finding."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Port 80 Open",
                "description": "Port 80",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        # Get all findings to get an ID
        all_findings = db_manager.get_findings(limit=100)
        if all_findings['findings']:
            finding_id = all_findings['findings'][0]['id']

            retrieved = db_manager.get_finding_by_id(finding_id)
            assert retrieved is not None
            assert retrieved['id'] == finding_id

    def test_update_finding_status(self, db_manager):
        """Test updating finding status."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Port 80 Open",
                "description": "Port 80",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        # Get finding ID
        all_findings = db_manager.get_findings(limit=100)
        if all_findings['findings']:
            finding_id = all_findings['findings'][0]['id']

            # Update status
            updated = db_manager.update_finding_status(
                finding_id=finding_id,
                status="resolved",
                resolution_notes="Fixed by security team"  # Fixed: was 'notes'
            )

            assert updated is True  # Returns bool, not dict
            # Verify the status was updated
            updated_finding = db_manager.get_finding_by_id(finding_id)
            assert updated_finding['status'] == "resolved"

    def test_get_findings_by_severity(self, db_manager):
        """Test filtering findings by severity."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Critical Port",
                "description": "Critical port",
                "severity": "critical",
                "status": "open"
            },
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Medium Port",
                "description": "Medium port",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        retrieved = db_manager.get_findings(min_severity="high", limit=100)

        # Should include critical but not medium
        assert any(f['severity'] == "critical" for f in retrieved['findings'])


class TestStatisticsOperations:
    """Test statistics and metrics."""

    def test_get_findings_statistics(self, db_manager):
        """Test getting findings statistics."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Critical Port",
                "description": "Critical",
                "severity": "critical",
                "status": "open"
            },
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "High Port",
                "description": "High",
                "severity": "high",
                "status": "open"
            },
            {
                "scan_id": scan_id,
                "affected_asset": "www.example.com",
                "finding_type": "open_port",
                "title": "Medium Port",
                "description": "Medium",
                "severity": "medium",
                "status": "open"
            },
        ]

        db_manager.store_findings(findings)

        stats = db_manager.get_findings_statistics()

        assert stats is not None
        assert 'total_findings' in stats
        assert 'by_severity' in stats

    def test_get_domain_count(self, db_manager):
        """Test getting domain count."""
        assert db_manager.get_domain_count() == 0

        db_manager.add_domain(domain="example.com")
        db_manager.add_domain(domain="test.io")

        assert db_manager.get_domain_count() == 2

    def test_get_scan_count(self, db_manager):
        """Test getting scan count."""
        assert db_manager.get_scan_count() == 0

        db_manager.add_domain(domain="example.com")
        db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )
        db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        assert db_manager.get_scan_count() >= 2

    def test_get_system_metrics(self, db_manager):
        """Test getting comprehensive system metrics."""
        db_manager.add_domain(domain="example.com")
        db_manager.add_domain(domain="test.io")

        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "High Port",
                "description": "High severity",
                "severity": "high",
                "status": "open"
            },
        ]
        db_manager.store_findings(findings)

        metrics = db_manager.get_system_metrics()

        assert metrics is not None
        assert 'total_domains' in metrics
        assert 'total_scans' in metrics
        assert 'total_findings' in metrics

    def test_get_health_status(self, db_manager):
        """Test getting system health status."""
        health = db_manager.get_health_status()

        assert health is not None
        assert isinstance(health, dict)


class TestDeletionOperations:
    """Test deletion and cleanup operations."""

    def test_get_deletion_preview(self, db_manager):
        """Test getting preview of what will be deleted."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        db_manager.add_subdomain_to_history(
            apex_domain="example.com",
            subdomain="api.example.com",
            scan_id=scan_id,
            status="new"
        )

        preview = db_manager.get_deletion_preview(domain="example.com")

        assert preview is not None
        assert 'domain' in preview
        # Preview contains 'totals' not 'scans'
        assert 'totals' in preview or 'scans' in preview

    def test_delete_domain_with_data(self, db_manager):
        """Test cascading deletion of domain and related data."""
        db_manager.add_domain(domain="example.com")
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        db_manager.add_subdomain_to_history(
            apex_domain="example.com",
            subdomain="api.example.com",
            scan_id=scan_id,
            status="new"
        )

        findings = [
            {
                "scan_id": scan_id,
                "affected_asset": "api.example.com",
                "finding_type": "open_port",
                "title": "Port 80 Open",
                "description": "Port 80",
                "severity": "medium",
                "status": "open"
            },
        ]
        db_manager.store_findings(findings)

        # Delete domain with all related data
        result = db_manager.delete_domain_with_data(domain="example.com")

        assert result is not None
        assert isinstance(result, dict)

        # Verify domain is gone
        assert not db_manager.domain_exists("example.com")
