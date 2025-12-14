"""
Tests for SQLModelManager - Database operations layer.

Focuses on job management methods since they are critical for the messaging layer.
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import patch

from src.data.database.sqlmodel_manager import SQLModelManager
from src.data.models.job import Job


@pytest.fixture
def db_manager():
    """Create a temporary database for testing."""
    # Use a unique temp file for each test
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)

    manager = SQLModelManager(db_path=db_path)
    manager.initialize()

    yield manager

    # Cleanup
    manager.close()
    if os.path.exists(db_path):
        os.remove(db_path)


class TestSQLModelManagerInit:
    """Tests for SQLModelManager initialization."""

    def test_init_creates_database(self):
        """Test initialization creates database file."""
        fd, db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(db_path)

        try:
            manager = SQLModelManager(db_path=db_path)
            manager.initialize()

            assert os.path.exists(db_path)
            manager.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_init_creates_parent_directory(self):
        """Test initialization creates parent directory if needed."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, 'subdir', 'test.db')

        try:
            manager = SQLModelManager(db_path=db_path)
            manager.initialize()

            assert os.path.exists(db_path)
            manager.close()
        finally:
            import shutil
            shutil.rmtree(temp_dir)


class TestJobManagement:
    """Tests for job CRUD operations."""

    def test_create_job(self, db_manager):
        """Test creating a job."""
        job = db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={'domain': 'example.com'},
            scan_id='scan-456',
            priority=50
        )

        assert job.id == 'job-123'
        assert job.job_type == 'scan'
        assert job.status == 'pending'
        assert job.scan_id == 'scan-456'
        assert job.priority == 50

    def test_create_job_default_priority(self, db_manager):
        """Test creating a job with default priority."""
        job = db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={'domain': 'example.com'}
        )

        assert job.priority == 100

    def test_get_job(self, db_manager):
        """Test retrieving a job by ID."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={'domain': 'example.com'}
        )

        job = db_manager.get_job('job-123')

        assert job is not None
        assert job['id'] == 'job-123'
        assert job['job_type'] == 'scan'
        assert job['payload'] == {'domain': 'example.com'}

    def test_get_job_not_found(self, db_manager):
        """Test retrieving a non-existent job."""
        job = db_manager.get_job('nonexistent')

        assert job is None

    def test_mark_job_queued(self, db_manager):
        """Test marking a job as queued."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )

        result = db_manager.mark_job_queued('job-123')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'queued'
        assert job['queued_at'] is not None

    def test_mark_job_queued_not_found(self, db_manager):
        """Test marking non-existent job as queued."""
        result = db_manager.mark_job_queued('nonexistent')

        assert result is False


class TestClaimJob:
    """Tests for atomic job claiming (race condition prevention)."""

    def test_claim_job_success(self, db_manager):
        """Test successfully claiming a pending job."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )

        result = db_manager.claim_job('job-123', 'worker-001')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'processing'
        assert job['worker_id'] == 'worker-001'
        assert job['started_at'] is not None

    def test_claim_job_queued_status(self, db_manager):
        """Test claiming a queued job."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.mark_job_queued('job-123')

        result = db_manager.claim_job('job-123', 'worker-001')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'processing'

    def test_claim_job_already_processing(self, db_manager):
        """Test claiming a job that's already being processed."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        # Second worker tries to claim
        result = db_manager.claim_job('job-123', 'worker-002')

        assert result is False
        # Original worker still has the job
        job = db_manager.get_job('job-123')
        assert job['worker_id'] == 'worker-001'

    def test_claim_job_completed(self, db_manager):
        """Test claiming a completed job fails."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')
        db_manager.complete_job('job-123', success=True)

        result = db_manager.claim_job('job-123', 'worker-002')

        assert result is False

    def test_claim_job_not_found(self, db_manager):
        """Test claiming a non-existent job."""
        result = db_manager.claim_job('nonexistent', 'worker-001')

        assert result is False


class TestCompleteJob:
    """Tests for job completion."""

    def test_complete_job_success(self, db_manager):
        """Test completing a job successfully."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        result = db_manager.complete_job('job-123', success=True)

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'completed'
        assert job['completed_at'] is not None

    def test_complete_job_failed(self, db_manager):
        """Test marking a job as failed with error message."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        result = db_manager.complete_job(
            'job-123',
            success=False,
            error_message='Connection timeout'
        )

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'failed'
        assert job['error_message'] == 'Connection timeout'

    def test_complete_job_truncates_long_error(self, db_manager):
        """Test that long error messages are truncated."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        long_error = 'x' * 3000
        db_manager.complete_job('job-123', success=False, error_message=long_error)

        job = db_manager.get_job('job-123')
        assert len(job['error_message']) == 2000

    def test_complete_job_not_found(self, db_manager):
        """Test completing a non-existent job."""
        result = db_manager.complete_job('nonexistent')

        assert result is False


class TestCancelJob:
    """Tests for atomic job cancellation."""

    def test_cancel_job_pending(self, db_manager):
        """Test cancelling a pending job."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )

        result = db_manager.cancel_job('job-123')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'cancelled'
        assert job['completed_at'] is not None

    def test_cancel_job_queued(self, db_manager):
        """Test cancelling a queued job."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.mark_job_queued('job-123')

        result = db_manager.cancel_job('job-123')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'cancelled'

    def test_cancel_job_processing_fails(self, db_manager):
        """Test cancelling a processing job fails."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        result = db_manager.cancel_job('job-123')

        assert result is False
        job = db_manager.get_job('job-123')
        assert job['status'] == 'processing'

    def test_cancel_job_completed_fails(self, db_manager):
        """Test cancelling a completed job fails."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')
        db_manager.complete_job('job-123', success=True)

        result = db_manager.cancel_job('job-123')

        assert result is False

    def test_cancel_job_not_found(self, db_manager):
        """Test cancelling a non-existent job."""
        result = db_manager.cancel_job('nonexistent')

        assert result is False


class TestRetryJob:
    """Tests for job retry functionality."""

    def test_retry_job_success(self, db_manager):
        """Test retrying a failed job."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')
        db_manager.complete_job('job-123', success=False, error_message='Error')

        result = db_manager.retry_job('job-123')

        assert result is True
        job = db_manager.get_job('job-123')
        assert job['status'] == 'pending'
        assert job['retry_count'] == 1
        assert job['worker_id'] is None
        assert job['started_at'] is None

    def test_retry_job_max_retries_exceeded(self, db_manager):
        """Test retry fails when max retries exceeded."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')
        db_manager.complete_job('job-123', success=False, error_message='Error')

        # Retry until max
        for _ in range(3):
            db_manager.retry_job('job-123')
            db_manager.claim_job('job-123', 'worker-001')
            db_manager.complete_job('job-123', success=False)

        # Should fail now
        result = db_manager.retry_job('job-123')

        assert result is False

    def test_retry_job_not_found(self, db_manager):
        """Test retrying a non-existent job."""
        result = db_manager.retry_job('nonexistent')

        assert result is False


class TestListJobs:
    """Tests for listing jobs."""

    def test_list_jobs_empty(self, db_manager):
        """Test listing jobs when none exist."""
        result = db_manager.list_jobs()

        assert result['jobs'] == []
        assert result['total'] == 0
        assert result['has_more'] is False

    def test_list_jobs_with_results(self, db_manager):
        """Test listing jobs with results."""
        db_manager.create_job(
            job_id='job-1',
            job_type='scan',
            payload={}
        )
        db_manager.create_job(
            job_id='job-2',
            job_type='analysis',
            payload={}
        )

        result = db_manager.list_jobs()

        assert len(result['jobs']) == 2
        assert result['total'] == 2

    def test_list_jobs_status_filter(self, db_manager):
        """Test listing jobs with status filter."""
        db_manager.create_job(
            job_id='job-1',
            job_type='scan',
            payload={}
        )
        db_manager.create_job(
            job_id='job-2',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-2', 'worker-001')

        result = db_manager.list_jobs(status='processing')

        assert len(result['jobs']) == 1
        assert result['jobs'][0]['id'] == 'job-2'

    def test_list_jobs_type_filter(self, db_manager):
        """Test listing jobs with type filter."""
        db_manager.create_job(
            job_id='job-1',
            job_type='scan',
            payload={}
        )
        db_manager.create_job(
            job_id='job-2',
            job_type='analysis',
            payload={}
        )

        result = db_manager.list_jobs(job_type='scan')

        assert len(result['jobs']) == 1
        assert result['jobs'][0]['job_type'] == 'scan'

    def test_list_jobs_pagination(self, db_manager):
        """Test listing jobs with pagination."""
        for i in range(5):
            db_manager.create_job(
                job_id=f'job-{i}',
                job_type='scan',
                payload={}
            )

        result = db_manager.list_jobs(limit=2, offset=0)

        assert len(result['jobs']) == 2
        assert result['total'] == 5
        assert result['has_more'] is True

        result2 = db_manager.list_jobs(limit=2, offset=4)

        assert len(result2['jobs']) == 1
        assert result2['has_more'] is False


class TestGetStaleJobs:
    """Tests for stale job detection."""

    def test_get_stale_jobs_none(self, db_manager):
        """Test no stale jobs when none are processing."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )

        result = db_manager.get_stale_jobs(stale_minutes=30)

        assert len(result) == 0

    def test_get_stale_jobs_recent_processing(self, db_manager):
        """Test recently started processing jobs are not stale."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')

        result = db_manager.get_stale_jobs(stale_minutes=30)

        assert len(result) == 0


class TestGetPendingJobs:
    """Tests for getting pending jobs."""

    def test_get_pending_jobs(self, db_manager):
        """Test getting pending jobs."""
        db_manager.create_job(
            job_id='job-1',
            job_type='scan',
            payload={}
        )
        db_manager.create_job(
            job_id='job-2',
            job_type='scan',
            payload={}
        )
        db_manager.mark_job_queued('job-2')

        result = db_manager.get_pending_jobs()

        assert len(result) == 1
        assert result[0]['id'] == 'job-1'

    def test_get_pending_jobs_limit(self, db_manager):
        """Test pending jobs respects limit."""
        for i in range(5):
            db_manager.create_job(
                job_id=f'job-{i}',
                job_type='scan',
                payload={}
            )

        result = db_manager.get_pending_jobs(limit=2)

        assert len(result) == 2


class TestJobStatistics:
    """Tests for job statistics."""

    def test_get_job_statistics_empty(self, db_manager):
        """Test job statistics when no jobs exist."""
        stats = db_manager.get_job_statistics()

        assert stats['total'] == 0
        assert stats['pending'] == 0
        assert stats['processing'] == 0
        assert stats['completed'] == 0
        assert stats['failed'] == 0
        assert stats['cancelled'] == 0

    def test_get_job_statistics(self, db_manager):
        """Test job statistics with various job states."""
        # Create jobs in different states
        db_manager.create_job(job_id='pending-1', job_type='scan', payload={})
        db_manager.create_job(job_id='pending-2', job_type='scan', payload={})

        db_manager.create_job(job_id='queued-1', job_type='scan', payload={})
        db_manager.mark_job_queued('queued-1')

        db_manager.create_job(job_id='processing-1', job_type='scan', payload={})
        db_manager.claim_job('processing-1', 'worker-001')

        db_manager.create_job(job_id='completed-1', job_type='scan', payload={})
        db_manager.claim_job('completed-1', 'worker-001')
        db_manager.complete_job('completed-1', success=True)

        db_manager.create_job(job_id='failed-1', job_type='scan', payload={})
        db_manager.claim_job('failed-1', 'worker-001')
        db_manager.complete_job('failed-1', success=False)

        db_manager.create_job(job_id='cancelled-1', job_type='scan', payload={})
        db_manager.cancel_job('cancelled-1')

        stats = db_manager.get_job_statistics()

        assert stats['total'] == 7
        assert stats['pending'] == 2
        assert stats['queued'] == 1
        assert stats['processing'] == 1
        assert stats['completed'] == 1
        assert stats['failed'] == 1
        assert stats['cancelled'] == 1


class TestCleanupOldJobs:
    """Tests for cleaning up old jobs."""

    def test_cleanup_old_jobs_none(self, db_manager):
        """Test cleanup when no jobs are old enough."""
        db_manager.create_job(
            job_id='job-123',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('job-123', 'worker-001')
        db_manager.complete_job('job-123', success=True)

        deleted = db_manager.cleanup_old_jobs(days=7)

        assert deleted == 0

    def test_cleanup_old_jobs_preserves_active(self, db_manager):
        """Test cleanup preserves pending/processing jobs."""
        db_manager.create_job(
            job_id='pending-1',
            job_type='scan',
            payload={}
        )
        db_manager.create_job(
            job_id='processing-1',
            job_type='scan',
            payload={}
        )
        db_manager.claim_job('processing-1', 'worker-001')

        deleted = db_manager.cleanup_old_jobs(days=0)

        assert deleted == 0
        assert db_manager.get_job('pending-1') is not None
        assert db_manager.get_job('processing-1') is not None


class TestHealthStatus:
    """Tests for database health check."""

    def test_get_health_status_healthy(self, db_manager):
        """Test health status when database is healthy."""
        status = db_manager.get_health_status()

        assert status['healthy'] is True
        assert status['database_connected'] is True
        assert status['tables_exist'] is True

    def test_get_health_status_with_data(self, db_manager):
        """Test health status with data in database."""
        # Add some data
        db_manager.add_domain('example.com')
        db_manager.create_job(job_id='job-1', job_type='scan', payload={})

        status = db_manager.get_health_status()

        assert status['healthy'] is True


# ============================================================================
# Domain Management Tests
# ============================================================================

class TestDomainManagement:
    """Tests for domain CRUD operations."""

    def test_add_domain_basic(self, db_manager):
        """Test adding a domain with basic info."""
        domain = db_manager.add_domain('example.com')

        assert domain.domain == 'example.com'
        assert domain.is_primary is False
        assert domain.scan_count == 0

    def test_add_domain_with_metadata(self, db_manager):
        """Test adding a domain with full metadata."""
        domain = db_manager.add_domain(
            domain='example.com',
            is_primary=True,
            contact_email='admin@example.com',
            scan_frequency='daily',
            active_scan_enabled=False
        )

        assert domain.domain == 'example.com'
        assert domain.is_primary is True
        assert domain.contact_email == 'admin@example.com'
        assert domain.scan_frequency == 'daily'
        assert domain.active_scan_enabled is False

    def test_get_domains_empty(self, db_manager):
        """Test getting domains when none exist."""
        result = db_manager.get_domains()

        assert result['domains'] == []
        assert result['total_count'] == 0
        assert result['has_more'] is False

    def test_get_domains_with_results(self, db_manager):
        """Test getting domains with results."""
        db_manager.add_domain('example1.com')
        db_manager.add_domain('example2.com')

        result = db_manager.get_domains()

        assert len(result['domains']) == 2
        assert result['total_count'] == 2

    def test_get_domains_primary_only(self, db_manager):
        """Test filtering domains by primary status."""
        db_manager.add_domain('primary.com', is_primary=True)
        db_manager.add_domain('secondary.com', is_primary=False)

        result = db_manager.get_domains(primary_only=True)

        assert len(result['domains']) == 1
        assert result['domains'][0].domain == 'primary.com'

    def test_get_domains_by_name(self, db_manager):
        """Test filtering domains by name."""
        db_manager.add_domain('example.com')
        db_manager.add_domain('test.com')

        result = db_manager.get_domains(domain_name='example.com')

        assert len(result['domains']) == 1
        assert result['domains'][0].domain == 'example.com'

    def test_get_domains_pagination(self, db_manager):
        """Test domain pagination."""
        for i in range(5):
            db_manager.add_domain(f'domain{i}.com')

        result = db_manager.get_domains(limit=2, offset=0)

        assert len(result['domains']) == 2
        assert result['total_count'] == 5
        assert result['has_more'] is True

    def test_update_domain(self, db_manager):
        """Test updating domain metadata."""
        db_manager.add_domain('example.com')

        updated = db_manager.update_domain(
            'example.com',
            is_primary=True,
            contact_email='new@example.com'
        )

        assert updated.is_primary is True
        assert updated.contact_email == 'new@example.com'

    def test_update_domain_not_found(self, db_manager):
        """Test updating non-existent domain raises error."""
        with pytest.raises(ValueError, match="not found"):
            db_manager.update_domain('nonexistent.com', is_primary=True)

    def test_increment_domain_scan_count(self, db_manager):
        """Test incrementing domain scan count."""
        db_manager.add_domain('example.com')

        updated = db_manager.increment_domain_scan_count('example.com')

        assert updated.scan_count == 1
        assert updated.last_scanned_at is not None

    def test_increment_domain_scan_count_not_found(self, db_manager):
        """Test incrementing scan count for non-existent domain."""
        with pytest.raises(ValueError, match="not found"):
            db_manager.increment_domain_scan_count('nonexistent.com')

    def test_delete_domain(self, db_manager):
        """Test deleting a domain."""
        db_manager.add_domain('example.com')

        result = db_manager.delete_domain('example.com')

        assert result is True
        assert db_manager.domain_exists('example.com') is False

    def test_delete_domain_not_found(self, db_manager):
        """Test deleting non-existent domain."""
        result = db_manager.delete_domain('nonexistent.com')

        assert result is False

    def test_domain_exists_true(self, db_manager):
        """Test domain_exists returns True for existing domain."""
        db_manager.add_domain('example.com')

        assert db_manager.domain_exists('example.com') is True

    def test_domain_exists_false(self, db_manager):
        """Test domain_exists returns False for non-existent domain."""
        assert db_manager.domain_exists('nonexistent.com') is False


# ============================================================================
# Scan Management Tests
# ============================================================================

class TestScanManagement:
    """Tests for scan session operations."""

    def test_create_scan_session(self, db_manager):
        """Test creating a scan session."""
        scan_id = db_manager.create_scan_session(
            scan_type='full_scan',
            domains=['example.com'],
            tool_name='subfinder'
        )

        assert scan_id is not None
        scan = db_manager.get_scan_status(scan_id)
        assert scan['status'] == 'running'
        assert scan['scan_type'] == 'full_scan'

    def test_update_scan_status(self, db_manager):
        """Test updating scan status."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.update_scan_status(
            scan_id,
            status='completed',
            findings_count=10
        )

        scan = db_manager.get_scan_status(scan_id)
        assert scan['status'] == 'completed'
        assert scan['findings_count'] == 10
        assert scan['end_time'] is not None

    def test_update_scan_status_not_found(self, db_manager):
        """Test updating non-existent scan raises error."""
        with pytest.raises(ValueError, match="not found"):
            db_manager.update_scan_status('nonexistent', status='completed')

    def test_get_scan_status_not_found(self, db_manager):
        """Test getting non-existent scan returns None."""
        result = db_manager.get_scan_status('nonexistent')

        assert result is None

    def test_get_scan_history_empty(self, db_manager):
        """Test scan history when none exist."""
        result = db_manager.get_scan_history()

        assert result['scans'] == []
        assert result['total_count'] == 0

    def test_get_scan_history_with_filters(self, db_manager):
        """Test scan history with filters."""
        db_manager.create_scan_session('full_scan', ['example.com'], 'subfinder')
        db_manager.create_scan_session('port_scan', ['test.com'], 'naabu')

        result = db_manager.get_scan_history(scan_type='full_scan')

        assert len(result['scans']) == 1
        assert result['scans'][0]['scan_type'] == 'full_scan'

    def test_delete_scan(self, db_manager):
        """Test deleting a scan session."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        result = db_manager.delete_scan(scan_id)

        assert result['success'] is True
        assert db_manager.get_scan_status(scan_id) is None

    def test_delete_scan_not_found(self, db_manager):
        """Test deleting non-existent scan raises error."""
        with pytest.raises(ValueError, match="not found"):
            db_manager.delete_scan('nonexistent')


# ============================================================================
# Findings Tests
# ============================================================================

class TestFindingsManagement:
    """Tests for findings operations."""

    def test_store_findings_new(self, db_manager):
        """Test storing new findings."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        result = db_manager.store_findings([{
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Port 22 Open',
            'severity': 'medium',
            'risk_score': 50,
            'port': 22
        }])

        assert result['new'] == 1
        assert result['updated'] == 0

    def test_store_findings_deduplication(self, db_manager):
        """Test findings deduplication on same asset/type/port."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        # First finding
        db_manager.store_findings([{
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Port 22 Open',
            'port': 22
        }])

        # Same finding again
        result = db_manager.store_findings([{
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Port 22 Open Updated',
            'port': 22
        }])

        assert result['new'] == 0
        assert result['updated'] == 1

    def test_get_findings_empty(self, db_manager):
        """Test getting findings when none exist."""
        result = db_manager.get_findings()

        assert result['findings'] == []
        assert result['total_count'] == 0

    def test_get_findings_with_filters(self, db_manager):
        """Test getting findings with filters."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([
            {
                'scan_id': scan_id,
                'finding_type': 'open_port',
                'affected_asset': 'example.com',
                'title': 'Port 22',
                'severity': 'high',
                'port': 22
            },
            {
                'scan_id': scan_id,
                'finding_type': 'open_port',
                'affected_asset': 'test.com',
                'title': 'Port 80',
                'severity': 'low',
                'port': 80
            }
        ])

        result = db_manager.get_findings(min_severity='high')

        assert len(result['findings']) == 1
        assert result['findings'][0]['severity'] == 'high'

    def test_get_finding_by_id(self, db_manager):
        """Test getting a finding by ID."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([{
            'id': 'finding-123',
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test Finding',
            'port': 22
        }])

        finding = db_manager.get_finding_by_id('finding-123')

        assert finding is not None
        assert finding['title'] == 'Test Finding'

    def test_get_finding_by_id_not_found(self, db_manager):
        """Test getting non-existent finding returns None."""
        result = db_manager.get_finding_by_id('nonexistent')

        assert result is None

    def test_update_finding_status(self, db_manager):
        """Test updating finding status."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([{
            'id': 'finding-123',
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test',
            'port': 22
        }])

        result = db_manager.update_finding_status(
            'finding-123',
            status='resolved',
            resolution_notes='Fixed by closing port'
        )

        assert result is True
        finding = db_manager.get_finding_by_id('finding-123')
        assert finding['status'] == 'resolved'

    def test_update_finding_status_invalid(self, db_manager):
        """Test updating finding with invalid status raises error."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([{
            'id': 'finding-123',
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test',
            'port': 22
        }])

        with pytest.raises(ValueError, match="Invalid status"):
            db_manager.update_finding_status('finding-123', status='invalid')

    def test_update_finding_status_not_found(self, db_manager):
        """Test updating non-existent finding returns False."""
        result = db_manager.update_finding_status('nonexistent', status='resolved')

        assert result is False

    def test_delete_finding(self, db_manager):
        """Test deleting a finding."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([{
            'id': 'finding-123',
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test',
            'port': 22
        }])

        result = db_manager.delete_finding('finding-123')

        assert result is True
        assert db_manager.get_finding_by_id('finding-123') is None

    def test_delete_finding_not_found(self, db_manager):
        """Test deleting non-existent finding returns False."""
        result = db_manager.delete_finding('nonexistent')

        assert result is False

    def test_get_findings_statistics(self, db_manager):
        """Test getting findings statistics."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([
            {
                'scan_id': scan_id,
                'finding_type': 'open_port',
                'affected_asset': 'example.com',
                'title': 'High Risk',
                'severity': 'high',
                'risk_score': 75,
                'port': 22
            },
            {
                'scan_id': scan_id,
                'finding_type': 'open_port',
                'affected_asset': 'example.com',
                'title': 'Low Risk',
                'severity': 'low',
                'risk_score': 25,
                'port': 80
            }
        ])

        stats = db_manager.get_findings_statistics()

        assert stats['total_findings'] == 2
        assert stats['high_findings'] == 1
        assert stats['low_findings'] == 1
        assert stats['average_risk_score'] == 50.0


# ============================================================================
# Alerts Tests (Backwards Compatibility)
# ============================================================================

class TestAlertsBackwardsCompatibility:
    """Tests for alerts API (backwards compatibility with findings)."""

    def test_store_alerts(self, db_manager):
        """Test storing alerts (maps to findings)."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        result = db_manager.store_alerts([{
            'domain': 'example.com',
            'scan_id': scan_id,
            'vulnerability_type': 'open_port',
            'severity': 'high',
            'description': 'Critical port exposed',
            'tool_source': 'naabu',
            'port': 22
        }])

        assert result['success'] is True
        assert result['count'] == 1

    def test_get_alerts(self, db_manager):
        """Test getting alerts (maps to findings)."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_alerts([{
            'domain': 'example.com',
            'scan_id': scan_id,
            'vulnerability_type': 'open_port',
            'severity': 'high',
            'description': 'Test Alert',
            'port': 22
        }])

        result = db_manager.get_alerts(domain='example.com')

        assert len(result['alerts']) == 1

    def test_get_alert_by_id(self, db_manager):
        """Test getting alert by ID (maps to finding)."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([{
            'id': 'alert-123',
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test',
            'port': 22
        }])

        alert = db_manager.get_alert_by_id('alert-123')

        assert alert is not None


# ============================================================================
# Tool Results Tests
# ============================================================================

class TestToolResults:
    """Tests for tool results storage."""

    def test_store_subfinder_results(self, db_manager):
        """Test storing subfinder results."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_subfinder_results([{
            'scan_id': scan_id,
            'apex_domain': 'example.com',
            'subdomain': 'api.example.com',
            'source': 'crtsh'
        }])

        results = db_manager.get_tool_results(scan_id, 'subfinder')
        assert results['total_count'] == 1

    def test_store_naabu_results(self, db_manager):
        """Test storing naabu results."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_naabu_results([{
            'scan_id': scan_id,
            'target_host': 'example.com',
            'port': 443,
            'protocol': 'tcp'
        }])

        results = db_manager.get_tool_results(scan_id, 'naabu')
        assert results['total_count'] == 1

    def test_store_nmap_results(self, db_manager):
        """Test storing nmap results."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_nmap_results([{
            'scan_id': scan_id,
            'target_host': 'example.com',
            'port': 22,
            'protocol': 'tcp',
            'service_name': 'ssh',
            'service_version': 'OpenSSH 8.0'
        }])

        results = db_manager.get_tool_results(scan_id, 'nmap')
        assert results['total_count'] == 1

    def test_store_amass_results(self, db_manager):
        """Test storing amass results."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_amass_results([{
            'scan_id': scan_id,
            'apex_domain': 'example.com',
            'subdomain': 'mail.example.com',
            'source': 'dns'
        }])

        results = db_manager.get_tool_results(scan_id, 'amass')
        assert results['total_count'] == 1

    def test_get_tool_results_unknown_tool(self, db_manager):
        """Test getting results for unknown tool raises error."""
        with pytest.raises(ValueError, match="Unknown tool"):
            db_manager.get_tool_results('scan-123', 'unknown_tool')


# ============================================================================
# Deletion Operations Tests
# ============================================================================

class TestDeletionOperations:
    """Tests for cascade deletion operations."""

    def test_get_deletion_preview(self, db_manager):
        """Test getting deletion preview for a domain."""
        db_manager.add_domain('example.com')
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_subfinder_results([{
            'scan_id': scan_id,
            'apex_domain': 'example.com',
            'subdomain': 'api.example.com'
        }])

        preview = db_manager.get_deletion_preview('example.com')

        assert preview['domain'] == 'example.com'
        assert preview['totals']['scan_sessions'] == 1
        assert preview['totals']['subfinder_results'] == 1

    def test_delete_domain_with_data(self, db_manager):
        """Test deleting domain cascades to all related data."""
        db_manager.add_domain('example.com')
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_subfinder_results([{
            'scan_id': scan_id,
            'apex_domain': 'example.com',
            'subdomain': 'api.example.com'
        }])

        deleted = db_manager.delete_domain_with_data('example.com')

        assert deleted['domain'] == 1
        assert deleted['scan_sessions'] == 1
        assert deleted['subfinder_results'] == 1
        assert db_manager.domain_exists('example.com') is False


# ============================================================================
# System Metrics Tests
# ============================================================================

class TestSystemMetrics:
    """Tests for system metrics."""

    def test_get_system_metrics_empty(self, db_manager):
        """Test system metrics when database is empty."""
        metrics = db_manager.get_system_metrics()

        assert metrics['total_domains'] == 0
        assert metrics['total_scans'] == 0
        assert metrics['total_alerts'] == 0

    def test_get_system_metrics_with_data(self, db_manager):
        """Test system metrics with data."""
        db_manager.add_domain('example.com', is_primary=True)
        db_manager.add_domain('test.com')
        scan_id = db_manager.create_scan_session('test', ['example.com'])
        db_manager.update_scan_status(scan_id, 'completed')

        db_manager.store_findings([{
            'scan_id': scan_id,
            'finding_type': 'open_port',
            'affected_asset': 'example.com',
            'title': 'Test',
            'severity': 'critical',
            'port': 22
        }])

        metrics = db_manager.get_system_metrics()

        assert metrics['total_domains'] == 2
        assert metrics['primary_domains'] == 1
        assert metrics['total_scans'] == 1
        assert metrics['completed_scans'] == 1
        assert metrics['critical_alerts'] == 1

    def test_get_domain_count(self, db_manager):
        """Test getting domain count."""
        db_manager.add_domain('example.com')
        db_manager.add_domain('test.com')

        count = db_manager.get_domain_count()

        assert count == 2

    def test_get_scan_count(self, db_manager):
        """Test getting scan count."""
        db_manager.create_scan_session('test1', ['example.com'])
        db_manager.create_scan_session('test2', ['test.com'])

        count = db_manager.get_scan_count()

        assert count == 2

    def test_get_alert_count(self, db_manager):
        """Test getting alert count."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_findings([
            {'scan_id': scan_id, 'finding_type': 'test1', 'affected_asset': 'a.com', 'title': 'T1', 'port': 22},
            {'scan_id': scan_id, 'finding_type': 'test2', 'affected_asset': 'b.com', 'title': 'T2', 'port': 80}
        ])

        count = db_manager.get_alert_count()

        assert count == 2


# ============================================================================
# Subdomain History Tests
# ============================================================================

class TestSubdomainHistory:
    """Tests for subdomain history tracking."""

    def test_add_subdomain_to_history(self, db_manager):
        """Test adding subdomain to history."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.add_subdomain_to_history(
            apex_domain='example.com',
            subdomain='api.example.com',
            scan_id=scan_id,
            status='new',
            tool_source='subfinder'
        )

        history = db_manager.get_subdomain_history('example.com')
        assert history['total_count'] == 1
        assert history['history'][0]['subdomain'] == 'api.example.com'

    def test_store_subdomain_history(self, db_manager):
        """Test store_subdomain_history alias."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        result = db_manager.store_subdomain_history(
            apex_domain='example.com',
            subdomain='mail.example.com',
            scan_id=scan_id
        )

        assert result['success'] is True

    def test_get_subdomain_changes(self, db_manager):
        """Test getting subdomain changes from a scan."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.add_subdomain_to_history('example.com', 'new.example.com', scan_id, 'new')
        db_manager.add_subdomain_to_history('example.com', 'existing.example.com', scan_id, 'existing')
        db_manager.add_subdomain_to_history('example.com', 'removed.example.com', scan_id, 'removed')

        changes = db_manager.get_subdomain_changes('example.com', scan_id)

        assert 'new.example.com' in changes['new']
        assert 'existing.example.com' in changes['existing']
        assert 'removed.example.com' in changes['removed']

    def test_get_discovered_subdomains(self, db_manager):
        """Test getting discovered subdomains from tool results."""
        scan_id = db_manager.create_scan_session('test', ['example.com'])

        db_manager.store_subfinder_results([
            {'scan_id': scan_id, 'apex_domain': 'example.com', 'subdomain': 'api.example.com'},
            {'scan_id': scan_id, 'apex_domain': 'example.com', 'subdomain': 'mail.example.com'}
        ])

        result = db_manager.get_discovered_subdomains('example.com')

        assert result['total_count'] == 2
