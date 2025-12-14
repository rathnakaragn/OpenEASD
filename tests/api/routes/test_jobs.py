"""
Tests for job queue API endpoints.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.dependencies import get_db_manager


# Test fixtures
@pytest.fixture
def mock_db():
    """Create a mock database manager."""
    return MagicMock()


@pytest.fixture
def client(mock_db):
    """Create a test client with mocked database."""
    app.dependency_overrides[get_db_manager] = lambda: mock_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


class TestListJobs:
    """Tests for GET /api/v1/jobs endpoint."""

    def test_list_jobs_empty(self, client, mock_db):
        """Test listing jobs when none exist."""
        mock_db.list_jobs.return_value = {
            'jobs': [],
            'total': 0,
            'limit': 20,
            'offset': 0,
            'has_more': False
        }

        response = client.get("/api/v1/jobs")

        assert response.status_code == 200
        data = response.json()
        assert data['jobs'] == []
        assert data['total_count'] == 0
        assert data['has_more'] is False

    def test_list_jobs_with_results(self, client, mock_db):
        """Test listing jobs with results."""
        mock_db.list_jobs.return_value = {
            'jobs': [
                {
                    'id': 'job-123',
                    'job_type': 'scan',
                    'payload': {'scan_id': 'scan-456', 'domain': 'example.com'},
                    'status': 'processing',
                    'scan_id': 'scan-456',
                    'worker_id': 'worker-001',
                    'created_at': '2025-12-04T10:00:00',
                    'queued_at': '2025-12-04T10:00:01',
                    'started_at': '2025-12-04T10:01:00',
                    'completed_at': None,
                    'error_message': None,
                    'retry_count': 0,
                    'max_retries': 3,
                    'priority': 100
                }
            ],
            'total': 1,
            'limit': 20,
            'offset': 0,
            'has_more': False
        }

        response = client.get("/api/v1/jobs")

        assert response.status_code == 200
        data = response.json()
        assert len(data['jobs']) == 1
        assert data['jobs'][0]['id'] == 'job-123'
        assert data['jobs'][0]['status'] == 'processing'
        assert data['total_count'] == 1

    def test_list_jobs_with_status_filter(self, client, mock_db):
        """Test listing jobs with status filter."""
        mock_db.list_jobs.return_value = {
            'jobs': [
                {
                    'id': 'job-123',
                    'job_type': 'scan',
                    'payload': {},
                    'status': 'failed',
                    'scan_id': None,
                    'worker_id': None,
                    'created_at': '2025-12-04T10:00:00',
                    'queued_at': None,
                    'started_at': None,
                    'completed_at': None,
                    'error_message': 'Connection timeout',
                    'retry_count': 3,
                    'max_retries': 3,
                    'priority': 100
                }
            ],
            'total': 1,
            'limit': 20,
            'offset': 0,
            'has_more': False
        }

        response = client.get("/api/v1/jobs?status=failed")

        assert response.status_code == 200
        mock_db.list_jobs.assert_called_with(
            status='failed',
            job_type=None,
            limit=20,
            offset=0
        )

    def test_list_jobs_with_pagination(self, client, mock_db):
        """Test listing jobs with pagination."""
        mock_db.list_jobs.return_value = {
            'jobs': [],
            'total': 100,
            'limit': 10,
            'offset': 20,
            'has_more': True
        }

        response = client.get("/api/v1/jobs?limit=10&offset=20")

        assert response.status_code == 200
        data = response.json()
        assert data['limit'] == 10
        assert data['offset'] == 20
        assert data['has_more'] is True


class TestGetJobStatistics:
    """Tests for GET /api/v1/jobs/statistics endpoint."""

    def test_get_job_statistics(self, client, mock_db):
        """Test getting job statistics."""
        mock_db.get_job_statistics.return_value = {
            'pending': 5,
            'queued': 3,
            'processing': 2,
            'completed': 100,
            'failed': 1,
            'cancelled': 0,
            'total': 111
        }

        response = client.get("/api/v1/jobs/statistics")

        assert response.status_code == 200
        data = response.json()
        assert data['pending'] == 5
        assert data['queued'] == 3
        assert data['processing'] == 2
        assert data['completed'] == 100
        assert data['failed'] == 1
        assert data['cancelled'] == 0
        assert data['total'] == 111

    def test_get_job_statistics_empty(self, client, mock_db):
        """Test getting job statistics when no jobs exist."""
        mock_db.get_job_statistics.return_value = {
            'pending': 0,
            'queued': 0,
            'processing': 0,
            'completed': 0,
            'failed': 0,
            'cancelled': 0,
            'total': 0
        }

        response = client.get("/api/v1/jobs/statistics")

        assert response.status_code == 200
        data = response.json()
        assert data['total'] == 0


class TestGetJob:
    """Tests for GET /api/v1/jobs/{job_id} endpoint."""

    def test_get_job_success(self, client, mock_db):
        """Test getting a specific job."""
        mock_db.get_job.return_value = {
            'id': 'job-123',
            'job_type': 'scan',
            'payload': {'scan_id': 'scan-456', 'domain': 'example.com'},
            'status': 'completed',
            'scan_id': 'scan-456',
            'worker_id': 'worker-001',
            'created_at': '2025-12-04T10:00:00',
            'queued_at': '2025-12-04T10:00:01',
            'started_at': '2025-12-04T10:01:00',
            'completed_at': '2025-12-04T10:05:00',
            'error_message': None,
            'retry_count': 0,
            'max_retries': 3,
            'priority': 100
        }

        response = client.get("/api/v1/jobs/job-123")

        assert response.status_code == 200
        data = response.json()
        assert data['id'] == 'job-123'
        assert data['status'] == 'completed'
        assert data['payload']['domain'] == 'example.com'

    def test_get_job_not_found(self, client, mock_db):
        """Test getting a non-existent job."""
        mock_db.get_job.return_value = None

        response = client.get("/api/v1/jobs/nonexistent-job")

        assert response.status_code == 404
        data = response.json()
        assert data['error_code'] == 'JOB_NOT_FOUND'


class TestRetryJob:
    """Tests for POST /api/v1/jobs/{job_id}/retry endpoint."""

    def test_retry_job_success(self, client, mock_db):
        """Test retrying a failed job."""
        # First call returns failed job, second call returns pending job after retry
        mock_db.get_job.side_effect = [
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'failed',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': None,
                'started_at': None,
                'completed_at': None,
                'error_message': 'Connection timeout',
                'retry_count': 0,
                'max_retries': 3,
                'priority': 100
            },
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'pending',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': None,
                'started_at': None,
                'completed_at': None,
                'error_message': None,
                'retry_count': 1,
                'max_retries': 3,
                'priority': 100
            }
        ]
        mock_db.retry_job.return_value = True

        response = client.post("/api/v1/jobs/job-123/retry")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'pending'
        assert data['retry_count'] == 1

    def test_retry_job_not_found(self, client, mock_db):
        """Test retrying a non-existent job."""
        mock_db.get_job.return_value = None

        response = client.post("/api/v1/jobs/nonexistent-job/retry")

        assert response.status_code == 404
        data = response.json()
        assert data['error_code'] == 'JOB_NOT_FOUND'

    def test_retry_job_not_failed(self, client, mock_db):
        """Test retrying a job that isn't failed."""
        mock_db.get_job.return_value = {
            'id': 'job-123',
            'job_type': 'scan',
            'payload': {},
            'status': 'processing',
            'scan_id': None,
            'worker_id': None,
            'created_at': '2025-12-04T10:00:00',
            'queued_at': None,
            'started_at': None,
            'completed_at': None,
            'error_message': None,
            'retry_count': 0,
            'max_retries': 3,
            'priority': 100
        }

        response = client.post("/api/v1/jobs/job-123/retry")

        assert response.status_code == 400
        data = response.json()
        assert data['error_code'] == 'JOB_CANNOT_BE_RETRIED'
        assert 'processing' in data['detail']

    def test_retry_job_max_retries_exceeded(self, client, mock_db):
        """Test retrying a job that has exceeded max retries."""
        mock_db.get_job.return_value = {
            'id': 'job-123',
            'job_type': 'scan',
            'payload': {},
            'status': 'failed',
            'scan_id': None,
            'worker_id': None,
            'created_at': '2025-12-04T10:00:00',
            'queued_at': None,
            'started_at': None,
            'completed_at': None,
            'error_message': 'Connection timeout',
            'retry_count': 3,
            'max_retries': 3,
            'priority': 100
        }

        response = client.post("/api/v1/jobs/job-123/retry")

        assert response.status_code == 400
        data = response.json()
        assert data['error_code'] == 'JOB_CANNOT_BE_RETRIED'
        assert 'max retries' in data['detail']


class TestCancelJob:
    """Tests for POST /api/v1/jobs/{job_id}/cancel endpoint."""

    def test_cancel_job_success(self, client, mock_db):
        """Test cancelling a pending job."""
        # First call returns pending job, second call returns cancelled job
        mock_db.get_job.side_effect = [
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'pending',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': None,
                'started_at': None,
                'completed_at': None,
                'error_message': None,
                'retry_count': 0,
                'max_retries': 3,
                'priority': 100
            },
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'cancelled',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': None,
                'started_at': None,
                'completed_at': '2025-12-04T10:00:30',
                'error_message': None,
                'retry_count': 0,
                'max_retries': 3,
                'priority': 100
            }
        ]
        mock_db.cancel_job.return_value = True

        response = client.post("/api/v1/jobs/job-123/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'cancelled'

    def test_cancel_queued_job_success(self, client, mock_db):
        """Test cancelling a queued job."""
        mock_db.get_job.side_effect = [
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'queued',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': '2025-12-04T10:00:01',
                'started_at': None,
                'completed_at': None,
                'error_message': None,
                'retry_count': 0,
                'max_retries': 3,
                'priority': 100
            },
            {
                'id': 'job-123',
                'job_type': 'scan',
                'payload': {},
                'status': 'cancelled',
                'scan_id': None,
                'worker_id': None,
                'created_at': '2025-12-04T10:00:00',
                'queued_at': '2025-12-04T10:00:01',
                'started_at': None,
                'completed_at': '2025-12-04T10:00:30',
                'error_message': None,
                'retry_count': 0,
                'max_retries': 3,
                'priority': 100
            }
        ]
        mock_db.cancel_job.return_value = True

        response = client.post("/api/v1/jobs/job-123/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'cancelled'

    def test_cancel_job_not_found(self, client, mock_db):
        """Test cancelling a non-existent job."""
        mock_db.get_job.return_value = None

        response = client.post("/api/v1/jobs/nonexistent-job/cancel")

        assert response.status_code == 404
        data = response.json()
        assert data['error_code'] == 'JOB_NOT_FOUND'

    def test_cancel_job_not_cancellable(self, client, mock_db):
        """Test cancelling a job that can't be cancelled."""
        mock_db.get_job.return_value = {
            'id': 'job-123',
            'job_type': 'scan',
            'payload': {},
            'status': 'processing',
            'scan_id': None,
            'worker_id': 'worker-001',
            'created_at': '2025-12-04T10:00:00',
            'queued_at': None,
            'started_at': '2025-12-04T10:01:00',
            'completed_at': None,
            'error_message': None,
            'retry_count': 0,
            'max_retries': 3,
            'priority': 100
        }

        response = client.post("/api/v1/jobs/job-123/cancel")

        assert response.status_code == 400
        data = response.json()
        assert data['error_code'] == 'JOB_CANNOT_BE_CANCELLED'
        assert 'processing' in data['detail']

    def test_cancel_completed_job(self, client, mock_db):
        """Test cancelling an already completed job."""
        mock_db.get_job.return_value = {
            'id': 'job-123',
            'job_type': 'scan',
            'payload': {},
            'status': 'completed',
            'scan_id': None,
            'worker_id': 'worker-001',
            'created_at': '2025-12-04T10:00:00',
            'queued_at': None,
            'started_at': '2025-12-04T10:01:00',
            'completed_at': '2025-12-04T10:05:00',
            'error_message': None,
            'retry_count': 0,
            'max_retries': 3,
            'priority': 100
        }

        response = client.post("/api/v1/jobs/job-123/cancel")

        assert response.status_code == 400
        data = response.json()
        assert data['error_code'] == 'JOB_CANNOT_BE_CANCELLED'
