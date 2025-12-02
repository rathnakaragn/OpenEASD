
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from datetime import datetime

from src.api.main import app
from src.api.dependencies import get_scan_service

client = TestClient(app)

# A sample scan that conforms to the ScanResponse schema
sample_scan = {
    "scan_id": "scan_123",
    "domain": "example.com",
    "scan_type": "full",
    "status": "completed",
    "start_time": datetime.now(),
    "end_time": datetime.now(),
    "findings_count": 10,
}

@pytest.fixture
def mock_scan_service():
    """Fixture for a mocked scan service."""
    service = MagicMock()
    service.list_scans.return_value = {'scans': [sample_scan], 'total': 1}
    service.get_scan_status.return_value = {'scan': sample_scan}
    service.get_scan_results.return_value = {
        'scan': sample_scan,
        'subdomains': [],
        'ports': []
    }
    return service

def test_list_scans(mock_scan_service):
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    assert response.json()['total'] == 1
    mock_scan_service.list_scans.assert_called()
    app.dependency_overrides = {}

def test_get_scan_status(mock_scan_service):
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get(f"/api/v1/scans/{sample_scan['scan_id']}")
    assert response.status_code == 200
    assert response.json()['scan_id'] == sample_scan['scan_id']
    mock_scan_service.get_scan_status.assert_called_with(sample_scan['scan_id'])
    app.dependency_overrides = {}

def test_get_scan_status_not_found(mock_scan_service):
    mock_scan_service.get_scan_status.side_effect = ValueError("Not found")
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get("/api/v1/scans/not-real")
    assert response.status_code == 404
    app.dependency_overrides = {}

def test_get_scan_results(mock_scan_service):
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get(f"/api/v1/scans/{sample_scan['scan_id']}/results")
    assert response.status_code == 200
    assert response.json()['scan']['scan_id'] == sample_scan['scan_id']
    mock_scan_service.get_scan_results.assert_called_with(sample_scan['scan_id'])
    app.dependency_overrides = {}

def test_get_scan_results_not_found(mock_scan_service):
    mock_scan_service.get_scan_results.side_effect = ValueError("Not found")
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get("/api/v1/scans/not-real/results")
    assert response.status_code == 404
    app.dependency_overrides = {}

def test_list_scans_error(mock_scan_service):
    mock_scan_service.list_scans.side_effect = KeyError("Missing field")
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get("/api/v1/scans")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_scan_status_error(mock_scan_service):
    mock_scan_service.get_scan_status.side_effect = KeyError("Missing field")
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get(f"/api/v1/scans/{sample_scan['scan_id']}")
    assert response.status_code == 500
    app.dependency_overrides = {}

def test_get_scan_results_error(mock_scan_service):
    mock_scan_service.get_scan_results.side_effect = KeyError("Missing field")
    app.dependency_overrides[get_scan_service] = lambda: mock_scan_service
    response = client.get(f"/api/v1/scans/{sample_scan['scan_id']}/results")
    assert response.status_code == 500
    app.dependency_overrides = {}
