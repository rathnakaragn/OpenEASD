import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from datetime import datetime

from src.api.main import app

client = TestClient(app)

# A sample alert that conforms to the AlertResponse schema
sample_alert = {
    "alert_id": "alert_12345",
    "scan_id": "scan_12345",
    "domain": "api.example.com",
    "vulnerability_type": "open_port",
    "severity": "low",
    "description": "Open port 443 (tcp)",
    "tool_source": "naabu",
    "discovered_at": datetime.now().isoformat(),
    "status": "open"
}

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts(mock_get_service):
    """Test the endpoint for listing alerts."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [sample_alert], 'total': 1}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts")
    
    assert response.status_code == 200
    mock_service.list_alerts.assert_called()
    assert response.json()['total'] == 1
    assert response.json()['alerts'][0]['alert_id'] == sample_alert['alert_id']

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_with_params(mock_get_service):
    """Test listing alerts with query parameters."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [], 'total': 0}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?limit=10&severity=high&domain=example.com")
    
    assert response.status_code == 200
    mock_service.list_alerts.assert_called_with(limit=10, severity='high', domain='example.com', min_severity=None)

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_error(mock_get_service):
    """Test error handling when listing alerts."""
    mock_service = MagicMock()
    mock_service.list_alerts.side_effect = Exception("Service error")
    mock_get_service.return_value = mock_service
    
    response = client.get("/api/v1/alerts")
    
    assert response.status_code == 500
    assert "Failed to list alerts" in response.text

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_statistics(mock_get_service):
    """Test the endpoint for alert statistics."""
    mock_service = MagicMock()
    mock_service.get_alert_statistics.return_value = {'statistics': {'total': 123, 'by_severity': {}, 'by_type': {}, 'by_tool': {}}}
    mock_get_service.return_value = mock_service
    
    response = client.get("/api/v1/alerts/statistics")
    
    assert response.status_code == 200
    mock_service.get_alert_statistics.assert_called()
    assert response.json()['total'] == 123

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_statistics_error(mock_get_service):
    """Test error handling for alert statistics."""
    mock_service = MagicMock()
    mock_service.get_alert_statistics.side_effect = Exception("Stats error")
    mock_get_service.return_value = mock_service
    
    response = client.get("/api/v1/alerts/statistics")
    
    assert response.status_code == 500
    assert "Failed to retrieve alert statistics" in response.text

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_by_id(mock_get_service):
    """Test retrieving a single alert by its ID."""
    mock_service = MagicMock()
    mock_service.get_alert.return_value = {'alert': sample_alert}
    mock_get_service.return_value = mock_service
    
    response = client.get(f"/api/v1/alerts/{sample_alert['alert_id']}")
    
    assert response.status_code == 200
    mock_service.get_alert.assert_called_with(sample_alert['alert_id'])
    assert response.json()['alert_id'] == sample_alert['alert_id']

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_not_found(mock_get_service):
    """Test retrieving a non-existent alert."""
    mock_service = MagicMock()
    mock_service.get_alert.side_effect = ValueError("Not found")
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts/not-real")

    assert response.status_code == 404

# Additional comprehensive tests for alerts API

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_all_severity_levels(mock_get_service):
    """Test list alerts with all valid severity levels."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [sample_alert], 'total': 1}
    mock_get_service.return_value = mock_service

    for severity in ['info', 'low', 'medium', 'high', 'critical']:
        response = client.get(f"/api/v1/alerts?severity={severity}")
        assert response.status_code == 200
        mock_service.list_alerts.assert_called_with(
            limit=50, severity=severity, domain=None, min_severity=None
        )

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_invalid_severity(mock_get_service):
    """Test list alerts with invalid severity level."""
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?severity=invalid")
    assert response.status_code == 422  # Unprocessable Entity

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_min_severity_filter(mock_get_service):
    """Test list alerts with minimum severity filter."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [], 'total': 0}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?min_severity=high")
    assert response.status_code == 200
    mock_service.list_alerts.assert_called_with(
        limit=50, severity=None, domain=None, min_severity='high'
    )

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_invalid_min_severity(mock_get_service):
    """Test list alerts with invalid minimum severity."""
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?min_severity=invalid")
    assert response.status_code == 422

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_domain_filter(mock_get_service):
    """Test list alerts with domain filter."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [sample_alert], 'total': 1}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?domain=api.example.com")
    assert response.status_code == 200
    mock_service.list_alerts.assert_called_with(
        limit=50, severity=None, domain='api.example.com', min_severity=None
    )

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_combined_filters(mock_get_service):
    """Test list alerts with multiple filters combined."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [], 'total': 0}
    mock_get_service.return_value = mock_service

    response = client.get(
        "/api/v1/alerts?limit=100&severity=high&domain=test.com&min_severity=medium"
    )
    assert response.status_code == 200
    mock_service.list_alerts.assert_called_with(
        limit=100, severity='high', domain='test.com', min_severity='medium'
    )

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_limit_boundary(mock_get_service):
    """Test list alerts with limit at boundaries."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [], 'total': 0}
    mock_get_service.return_value = mock_service

    # Test minimum limit
    response = client.get("/api/v1/alerts?limit=1")
    assert response.status_code == 200

    # Test maximum limit
    response = client.get("/api/v1/alerts?limit=200")
    assert response.status_code == 200

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_invalid_limit_too_high(mock_get_service):
    """Test list alerts with limit exceeding maximum."""
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?limit=201")
    assert response.status_code == 422

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_invalid_limit_zero(mock_get_service):
    """Test list alerts with limit of zero."""
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?limit=0")
    assert response.status_code == 422

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_invalid_limit_negative(mock_get_service):
    """Test list alerts with negative limit."""
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts?limit=-1")
    assert response.status_code == 422

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_multiple_results(mock_get_service):
    """Test listing multiple alerts."""
    alert2 = {
        "alert_id": "alert_67890",
        "scan_id": "scan_67890",
        "domain": "api2.example.com",
        "vulnerability_type": "exposed_service",
        "severity": "high",
        "description": "Exposed admin interface",
        "tool_source": "httpx",
        "discovered_at": datetime.now().isoformat(),
        "status": "open"
    }
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [sample_alert, alert2], 'total': 2}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json()['total'] == 2
    assert len(response.json()['alerts']) == 2

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_empty_results(mock_get_service):
    """Test listing when no alerts exist."""
    mock_service = MagicMock()
    mock_service.list_alerts.return_value = {'alerts': [], 'total': 0}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json()['total'] == 0
    assert len(response.json()['alerts']) == 0

@patch('src.api.routes.alerts.get_alert_service')
def test_list_alerts_value_error(mock_get_service):
    """Test list alerts with ValueError from service."""
    mock_service = MagicMock()
    mock_service.list_alerts.side_effect = ValueError("Invalid filter parameter")
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts")
    assert response.status_code == 400

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_by_id_success(mock_get_service):
    """Test getting a single alert by ID."""
    mock_service = MagicMock()
    mock_service.get_alert.return_value = {'alert': sample_alert}
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts/alert_12345")
    assert response.status_code == 200
    data = response.json()
    assert data['alert_id'] == sample_alert['alert_id']
    assert data['domain'] == sample_alert['domain']
    assert data['severity'] == sample_alert['severity']

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_server_error(mock_get_service):
    """Test getting alert with server error."""
    mock_service = MagicMock()
    mock_service.get_alert.side_effect = Exception("Database connection failed")
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts/alert_12345")
    assert response.status_code == 500

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_statistics_structure(mock_get_service):
    """Test alert statistics response structure."""
    mock_service = MagicMock()
    mock_service.get_alert_statistics.return_value = {
        'statistics': {
            'total': 100,
            'by_severity': {'critical': 5, 'high': 20, 'medium': 30, 'low': 40, 'info': 5},
            'by_type': {'open_port': 50, 'exposed_service': 30, 'other': 20},
            'by_tool': {'naabu': 60, 'httpx': 40}
        }
    }
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts/statistics")
    assert response.status_code == 200
    data = response.json()
    assert 'total' in data
    assert 'by_severity' in data
    assert 'by_type' in data
    assert 'by_tool' in data

@patch('src.api.routes.alerts.get_alert_service')
def test_get_alert_statistics_empty(mock_get_service):
    """Test alert statistics with zero alerts."""
    mock_service = MagicMock()
    mock_service.get_alert_statistics.return_value = {
        'statistics': {
            'total': 0,
            'by_severity': {},
            'by_type': {},
            'by_tool': {}
        }
    }
    mock_get_service.return_value = mock_service

    response = client.get("/api/v1/alerts/statistics")
    assert response.status_code == 200
    assert response.json()['total'] == 0