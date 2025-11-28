"""
Comprehensive test suite for API findings routes.

Tests all endpoints in src/api/routes/findings.py with proper dependency injection.
"""

import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from src.api.main import app
from src.api.dependencies import get_db_manager


@pytest.fixture(autouse=True)
def reset_dependencies():
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    return MagicMock()


@pytest.fixture
def sample_finding():
    """Create sample finding data."""
    return {
        'id': 'f-001',
        'scan_id': 's-001',
        'affected_asset': 'api.example.com',
        'finding_type': 'database_exposure',
        'severity': 'critical',
        'description': 'MySQL port exposed',
        'evidence': {'port': 3306},
        'risk_score': 85,
        'score_breakdown': {'base': 40, 'context': 30, 'exposure': 15},
        'status': 'open',
        'resolution_notes': None,
        'created_at': '2025-11-28T10:00:00Z',
        'updated_at': '2025-11-28T10:00:00Z'
    }


class TestListFindingsEndpoint:
    """Test GET /findings/ endpoint."""

    def test_list_findings_default_params(self, client, mock_db_manager, sample_finding):
        """Test listing findings with default parameters."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 1
        assert data['total'] == 1

    def test_list_findings_with_scan_filter(self, client, mock_db_manager, sample_finding):
        """Test filtering by scan ID."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/?scan_id=s-001')
        assert response.status_code == 200
        mock_db_manager.get_findings.assert_called_once()

    def test_list_findings_with_asset_filter(self, client, mock_db_manager, sample_finding):
        """Test filtering by affected asset."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/?affected_asset=api.example.com')
        assert response.status_code == 200

    def test_list_findings_with_severity_filter(self, client, mock_db_manager, sample_finding):
        """Test filtering by minimum severity."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/?min_severity=high')
        assert response.status_code == 200

    def test_list_findings_pagination(self, client, mock_db_manager, sample_finding):
        """Test pagination parameters."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 100,
            'limit': 10,
            'offset': 10
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/?limit=10&offset=10')
        assert response.status_code == 200
        data = response.json()
        assert data['limit'] == 10
        assert data['offset'] == 10

    def test_list_findings_empty(self, client, mock_db_manager):
        """Test when no findings exist."""
        mock_db_manager.get_findings.return_value = {
            'findings': [],
            'total': 0,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 0

    def test_list_findings_db_error(self, client, mock_db_manager):
        """Test database error handling."""
        mock_db_manager.get_findings.side_effect = Exception("DB connection error")
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/')
        assert response.status_code == 500
        assert "Failed to retrieve findings" in response.json()['detail']


class TestGetFindingEndpoint:
    """Test GET /findings/{finding_id} endpoint."""

    def test_get_finding_success(self, client, mock_db_manager, sample_finding):
        """Test retrieving a single finding."""
        mock_db_manager.get_finding_by_id.return_value = sample_finding
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/f-001')
        assert response.status_code == 200
        data = response.json()
        assert data['id'] == 'f-001'
        assert data['severity'] == 'critical'

    def test_get_finding_not_found(self, client, mock_db_manager):
        """Test when finding doesn't exist."""
        mock_db_manager.get_finding_by_id.return_value = None
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/nonexistent')
        assert response.status_code == 404
        assert "not found" in response.json()['detail']

    def test_get_finding_with_scores(self, client, mock_db_manager, sample_finding):
        """Test that risk score breakdown is returned."""
        mock_db_manager.get_finding_by_id.return_value = sample_finding
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/f-001')
        assert response.status_code == 200
        data = response.json()
        assert 'score_breakdown' in data

    def test_get_finding_db_error(self, client, mock_db_manager):
        """Test database error handling."""
        mock_db_manager.get_finding_by_id.side_effect = Exception("DB error")
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/f-001')
        assert response.status_code == 500


class TestFindingsStatisticsEndpoint:
    """Test GET /findings/statistics/summary endpoint."""

    def test_get_statistics_success(self, client, mock_db_manager):
        """Test retrieving findings statistics."""
        stats = {
            'total_findings': 10,
            'by_severity': {'critical': 2, 'high': 3, 'medium': 4, 'low': 1, 'info': 0},
            'by_status': {'open': 8, 'acknowledged': 1, 'resolved': 1, 'false_positive': 0},
            'average_risk_score': 65.5
        }
        mock_db_manager.get_findings_statistics.return_value = stats
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/statistics/summary')
        assert response.status_code == 200
        data = response.json()
        assert data['total_findings'] == 10
        assert data['by_severity']['critical'] == 2

    def test_statistics_with_scan_filter(self, client, mock_db_manager):
        """Test statistics filtered by scan."""
        stats = {
            'total_findings': 5,
            'by_severity': {'critical': 1, 'high': 2, 'medium': 2, 'low': 0, 'info': 0},
            'by_status': {'open': 5, 'acknowledged': 0, 'resolved': 0, 'false_positive': 0},
            'average_risk_score': 60.0
        }
        mock_db_manager.get_findings_statistics.return_value = stats
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/statistics/summary?scan_id=s-001')
        assert response.status_code == 200

    def test_statistics_with_asset_filter(self, client, mock_db_manager):
        """Test statistics filtered by asset."""
        stats = {
            'total_findings': 2,
            'by_severity': {'critical': 1, 'high': 1, 'medium': 0, 'low': 0, 'info': 0},
            'by_status': {'open': 2, 'acknowledged': 0, 'resolved': 0, 'false_positive': 0},
            'average_risk_score': 75.0
        }
        mock_db_manager.get_findings_statistics.return_value = stats
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/statistics/summary?affected_asset=example.com')
        assert response.status_code == 200

    def test_statistics_no_findings(self, client, mock_db_manager):
        """Test statistics when no findings exist."""
        stats = {
            'total_findings': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_status': {'open': 0, 'acknowledged': 0, 'resolved': 0, 'false_positive': 0},
            'average_risk_score': 0
        }
        mock_db_manager.get_findings_statistics.return_value = stats
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/statistics/summary')
        assert response.status_code == 200
        data = response.json()
        assert data['total_findings'] == 0


class TestUpdateFindingStatusEndpoint:
    """Test PATCH /findings/{finding_id}/status endpoint."""

    def test_update_status_resolved(self, client, mock_db_manager):
        """Test updating finding to resolved status."""
        mock_db_manager.update_finding_status.return_value = True
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.patch(
            '/api/v1/findings/f-001/status',
            json={'status': 'resolved', 'resolution_notes': 'Fixed'}
        )
        assert response.status_code == 200
        assert 'resolved' in response.json()['message']

    def test_update_status_acknowledged(self, client, mock_db_manager):
        """Test updating finding to acknowledged status."""
        mock_db_manager.update_finding_status.return_value = True
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.patch(
            '/api/v1/findings/f-001/status',
            json={'status': 'acknowledged', 'resolution_notes': 'In progress'}
        )
        assert response.status_code == 200

    def test_update_status_false_positive(self, client, mock_db_manager):
        """Test marking finding as false positive."""
        mock_db_manager.update_finding_status.return_value = True
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.patch(
            '/api/v1/findings/f-001/status',
            json={'status': 'false_positive', 'resolution_notes': 'Not applicable'}
        )
        assert response.status_code == 200

    def test_update_status_not_found(self, client, mock_db_manager):
        """Test updating non-existent finding."""
        mock_db_manager.update_finding_status.return_value = False
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.patch(
            '/api/v1/findings/nonexistent/status',
            json={'status': 'resolved'}
        )
        assert response.status_code == 404

    def test_update_status_without_notes(self, client, mock_db_manager):
        """Test updating status without resolution notes."""
        mock_db_manager.update_finding_status.return_value = True
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.patch(
            '/api/v1/findings/f-001/status',
            json={'status': 'acknowledged'}
        )
        assert response.status_code == 200


class TestScanFindingsEndpoint:
    """Test GET /findings/scan/{scan_id} endpoint."""

    def test_get_scan_findings_success(self, client, mock_db_manager, sample_finding):
        """Test retrieving findings for a scan."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/scan/s-001')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 1

    def test_scan_findings_with_severity_filter(self, client, mock_db_manager, sample_finding):
        """Test scan findings with severity filter."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/scan/s-001?min_severity=critical')
        assert response.status_code == 200

    def test_scan_findings_empty(self, client, mock_db_manager):
        """Test scan with no findings."""
        mock_db_manager.get_findings.return_value = {
            'findings': [],
            'total': 0,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/scan/s-001')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 0


class TestAssetFindingsEndpoint:
    """Test GET /findings/asset/{asset_name} endpoint."""

    def test_get_asset_findings_success(self, client, mock_db_manager, sample_finding):
        """Test retrieving findings for an asset."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/asset/example.com')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 1

    def test_asset_findings_with_severity_filter(self, client, mock_db_manager, sample_finding):
        """Test asset findings with severity filter."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/asset/api.example.com?min_severity=high')
        assert response.status_code == 200

    def test_asset_findings_no_results(self, client, mock_db_manager):
        """Test asset with no findings."""
        mock_db_manager.get_findings.return_value = {
            'findings': [],
            'total': 0,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/asset/unscanned.com')
        assert response.status_code == 200
        data = response.json()
        assert len(data['findings']) == 0

    def test_asset_findings_for_subdomain(self, client, mock_db_manager, sample_finding):
        """Test findings for a specific subdomain."""
        mock_db_manager.get_findings.return_value = {
            'findings': [sample_finding],
            'total': 1,
            'limit': 100,
            'offset': 0
        }
        app.dependency_overrides[get_db_manager] = lambda: mock_db_manager

        response = client.get('/api/v1/findings/asset/api.example.com')
        assert response.status_code == 200
