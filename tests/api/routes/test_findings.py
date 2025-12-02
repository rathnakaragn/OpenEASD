
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from datetime import datetime

from src.api.main import app
from src.api.dependencies import get_findings_service
from src.services.findings_service import FindingNotFound

client = TestClient(app)

# A sample finding that conforms to the FindingResponse schema
sample_finding = {
    "id": "finding_123",
    "scan_id": "scan_abc",
    "finding_type": "open_port",
    "affected_asset": "test.com",
    "title": "Open Port 80",
    "severity": "medium",
    "risk_score": 50,
    "status": "open",
    "false_positive": False,
    "discovered_at": datetime.now(),
    "updated_at": datetime.now(),
}

@pytest.fixture
def mock_findings_service():
    """Fixture for a mocked findings service."""
    service = MagicMock()
    service.list_findings.return_value = {
        'findings': [sample_finding], 
        'total_count': 1, 
        'has_more': False,
        'limit': 100,
        'offset': 0
    }
    service.get_statistics.return_value = {
        'total_findings': 1, 'by_severity': {}, 'by_status': {}, 'average_risk_score': 50.0,
        'critical_findings': 0, 'high_findings': 0, 'medium_findings': 1, 'low_findings': 0,
        'info_findings': 0, 'open_findings': 1, 'resolved_findings': 0, 'false_positives': 0
    }
    service.get_finding.return_value = sample_finding
    service.get_findings_by_scan.return_value = service.list_findings.return_value
    service.get_findings_by_asset.return_value = service.list_findings.return_value
    return service

def test_list_findings(mock_findings_service):
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/")
    assert response.status_code == 200
    assert response.json()['total_count'] == 1
    mock_findings_service.list_findings.assert_called()
    app.dependency_overrides = {}

def test_get_findings_statistics(mock_findings_service):
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/statistics/summary")
    assert response.status_code == 200
    assert response.json()['total_findings'] == 1
    mock_findings_service.get_statistics.assert_called()
    app.dependency_overrides = {}

def test_get_scan_findings(mock_findings_service):
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/scan/scan_abc")
    assert response.status_code == 200
    mock_findings_service.get_findings_by_scan.assert_called_with(scan_id='scan_abc', min_severity=None, limit=100, offset=0)
    app.dependency_overrides = {}

def test_get_asset_findings(mock_findings_service):
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/asset/test.com")
    assert response.status_code == 200
    mock_findings_service.get_findings_by_asset.assert_called_with(asset_name='test.com', min_severity=None, limit=100, offset=0)
    app.dependency_overrides = {}

def test_get_finding_by_id(mock_findings_service):
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/finding_123")
    assert response.status_code == 200
    assert response.json()['id'] == 'finding_123'
    mock_findings_service.get_finding.assert_called_with('finding_123')
    app.dependency_overrides = {}

def test_get_finding_not_found(mock_findings_service):
    mock_findings_service.get_finding.side_effect = FindingNotFound
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/not_real")
    assert response.status_code == 404
    app.dependency_overrides = {}

def test_list_findings_error(mock_findings_service):
    mock_findings_service.list_findings.side_effect = Exception("Service Error")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_statistics_error(mock_findings_service):
    mock_findings_service.get_statistics.side_effect = Exception("Service Error")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/statistics/summary")
    assert response.status_code == 500
    app.dependency_overrides = {}

# Additional comprehensive tests for findings API

def test_list_findings_with_filters(mock_findings_service):
    """Test listing findings with multiple filters."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?scan_id=scan_123&affected_asset=test.com&min_severity=high")
    assert response.status_code == 200
    mock_findings_service.list_findings.assert_called_with(
        scan_id='scan_123',
        affected_asset='test.com',
        min_severity='high',
        limit=100,
        offset=0
    )
    app.dependency_overrides = {}

def test_list_findings_with_pagination(mock_findings_service):
    """Test listing findings with custom pagination."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?limit=50&offset=10")
    assert response.status_code == 200
    mock_findings_service.list_findings.assert_called_with(
        scan_id=None,
        affected_asset=None,
        min_severity=None,
        limit=50,
        offset=10
    )
    app.dependency_overrides = {}

def test_list_findings_invalid_limit_too_high(mock_findings_service):
    """Test that limit beyond maximum is rejected."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?limit=2000")
    assert response.status_code == 422  # Unprocessable Entity
    app.dependency_overrides = {}

def test_list_findings_invalid_limit_zero(mock_findings_service):
    """Test that limit of 0 is rejected."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?limit=0")
    assert response.status_code == 422  # Unprocessable Entity
    app.dependency_overrides = {}

def test_list_findings_invalid_negative_offset(mock_findings_service):
    """Test that negative offset is rejected."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?offset=-1")
    assert response.status_code == 422  # Unprocessable Entity
    app.dependency_overrides = {}

def test_list_findings_multiple_results(mock_findings_service):
    """Test listing multiple findings."""
    finding2 = {
        "id": "finding_456",
        "scan_id": "scan_def",
        "finding_type": "exposed_service",
        "affected_asset": "api.test.com",
        "title": "Exposed Admin Interface",
        "severity": "high",
        "risk_score": 75,
        "status": "open",
        "false_positive": False,
        "discovered_at": datetime.now(),
        "updated_at": datetime.now(),
    }
    mock_findings_service.list_findings.return_value = {
        'findings': [sample_finding, finding2],
        'total_count': 2,
        'has_more': False,
        'limit': 100,
        'offset': 0
    }
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/")
    assert response.status_code == 200
    assert response.json()['total_count'] == 2
    assert len(response.json()['findings']) == 2
    app.dependency_overrides = {}

def test_list_findings_empty_results(mock_findings_service):
    """Test listing when no findings exist."""
    mock_findings_service.list_findings.return_value = {
        'findings': [],
        'total_count': 0,
        'has_more': False,
        'limit': 100,
        'offset': 0
    }
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/")
    assert response.status_code == 200
    assert response.json()['total_count'] == 0
    assert len(response.json()['findings']) == 0
    app.dependency_overrides = {}

def test_list_findings_with_has_more(mock_findings_service):
    """Test listing findings with pagination has_more flag."""
    mock_findings_service.list_findings.return_value = {
        'findings': [sample_finding],
        'total_count': 150,
        'has_more': True,
        'limit': 100,
        'offset': 0
    }
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/")
    assert response.status_code == 200
    assert response.json()['has_more'] == True
    app.dependency_overrides = {}

def test_get_statistics_with_filters(mock_findings_service):
    """Test getting statistics with scan_id and asset filters."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/statistics/summary?scan_id=scan_123&affected_asset=test.com")
    assert response.status_code == 200
    mock_findings_service.get_statistics.assert_called_with(
        scan_id='scan_123',
        affected_asset='test.com'
    )
    app.dependency_overrides = {}

def test_get_statistics_error_detailed(mock_findings_service):
    """Test statistics endpoint handles ValueError properly."""
    mock_findings_service.get_statistics.side_effect = ValueError("Invalid parameters")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/statistics/summary")
    assert response.status_code == 400
    app.dependency_overrides = {}

def test_get_scan_findings_not_found(mock_findings_service):
    """Test getting findings for non-existent scan."""
    mock_findings_service.get_findings_by_scan.side_effect = ValueError("Scan not found")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/scan/invalid_scan")
    assert response.status_code == 404
    app.dependency_overrides = {}

def test_get_scan_findings_with_filters(mock_findings_service):
    """Test getting findings for a scan with severity filter."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/scan/scan_abc?min_severity=critical&limit=50&offset=5")
    assert response.status_code == 200
    mock_findings_service.get_findings_by_scan.assert_called_with(
        scan_id='scan_abc',
        min_severity='critical',
        limit=50,
        offset=5
    )
    app.dependency_overrides = {}

def test_get_scan_findings_error(mock_findings_service):
    """Test scan findings endpoint error handling."""
    mock_findings_service.get_findings_by_scan.side_effect = Exception("Database error")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/scan/scan_abc")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_asset_findings_invalid_asset(mock_findings_service):
    """Test getting findings for invalid asset name."""
    mock_findings_service.get_findings_by_asset.side_effect = ValueError("Invalid asset")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/asset/invalid")
    assert response.status_code == 400
    app.dependency_overrides = {}

def test_get_asset_findings_with_filters(mock_findings_service):
    """Test getting findings for asset with severity filter."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/asset/example.com?min_severity=high&limit=25")
    assert response.status_code == 200
    mock_findings_service.get_findings_by_asset.assert_called_with(
        asset_name='example.com',
        min_severity='high',
        limit=25,
        offset=0
    )
    app.dependency_overrides = {}

def test_get_asset_findings_error(mock_findings_service):
    """Test asset findings endpoint error handling."""
    mock_findings_service.get_findings_by_asset.side_effect = Exception("Service error")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/asset/test.com")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_finding_server_error(mock_findings_service):
    """Test getting a finding with server error."""
    mock_findings_service.get_finding.side_effect = Exception("Database connection failed")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/finding_123")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_finding_response_structure(mock_findings_service):
    """Test that get finding returns complete finding object."""
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/finding_123")
    assert response.status_code == 200
    data = response.json()
    assert 'id' in data
    assert 'scan_id' in data
    assert 'finding_type' in data
    assert 'affected_asset' in data
    assert 'title' in data
    assert 'severity' in data
    assert 'risk_score' in data
    assert 'status' in data
    assert 'false_positive' in data
    assert 'discovered_at' in data
    assert 'updated_at' in data
    app.dependency_overrides = {}

def test_list_findings_invalid_parameters_error(mock_findings_service):
    """Test listing findings with invalid parameters raises 400."""
    mock_findings_service.list_findings.side_effect = ValueError("Invalid severity")
    app.dependency_overrides[get_findings_service] = lambda: mock_findings_service
    response = client.get("/api/v1/findings/?min_severity=invalid")
    assert response.status_code == 400
    app.dependency_overrides = {}
