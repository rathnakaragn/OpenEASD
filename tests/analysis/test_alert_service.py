
import pytest
from unittest.mock import MagicMock, patch
from src.analysis.alert_service import AlertManagementService

@pytest.fixture
def db_manager_mock():
    """Fixture for a mocked database manager."""
    return MagicMock()

@pytest.fixture
def alert_service(db_manager_mock):
    """Fixture for AlertManagementService with a mocked db_manager."""
    return AlertManagementService(db_manager=db_manager_mock)

@pytest.fixture
def alert_service_no_db():
    """Fixture for AlertManagementService without a db_manager."""
    return AlertManagementService()

def test_initialization(alert_service, db_manager_mock):
    """Test if the service initializes correctly."""
    assert alert_service is not None
    assert alert_service.db_manager == db_manager_mock

def test_calculate_risk_score():
    """Test the risk score calculation."""
    assert AlertManagementService._calculate_risk_score('critical') == 90
    assert AlertManagementService._calculate_risk_score('high') == 70
    assert AlertManagementService._calculate_risk_score('medium') == 50
    assert AlertManagementService._calculate_risk_score('low') == 30
    assert AlertManagementService._calculate_risk_score('info') == 10
    assert AlertManagementService._calculate_risk_score('unknown') == 50

def test_get_base_score():
    """Test the base score calculation."""
    assert AlertManagementService._get_base_score('critical') == 40
    assert AlertManagementService._get_base_score('high') == 30
    assert AlertManagementService._get_base_score('medium') == 20
    assert AlertManagementService._get_base_score('low') == 10
    assert AlertManagementService._get_base_score('info') == 5
    assert AlertManagementService._get_base_score('unknown') == 20

@patch('src.analysis.alert_service.get_ist_now')
def test_create_alert_from_scan(mock_get_ist_now, alert_service):
    """Test creating a single alert from a scan."""
    mock_get_ist_now.return_value = '2025-12-02T12:00:00+05:30'
    
    scan_id = "test_scan_id"
    domain = "example.com"
    vulnerability_type = "open_port"
    severity = "high"
    description = "Port 80 is open"
    tool_source = "naabu"

    alert = alert_service.create_alert_from_scan(
        scan_id=scan_id,
        domain=domain,
        vulnerability_type=vulnerability_type,
        severity=severity,
        description=description,
        tool_source=tool_source
    )

    assert 'id' in alert
    assert alert['scan_id'] == scan_id
    assert alert['affected_asset'] == domain
    assert alert['finding_type'] == 'port_exposed'
    assert alert['severity'] == severity
    assert alert['risk_score'] == 70
    assert alert['detector'] == tool_source
    assert alert['status'] == 'open'

def test_finding_to_alert():
    """Test the conversion of a finding to an alert."""
    finding = {
        'id': 'finding_123',
        'scan_id': 'scan_abc',
        'affected_asset': 'test.com',
        'finding_type': 'open_port',
        'severity': 'high',
        'title': 'Port 8080 open',
        'description': 'Port 8080 is open and accessible.',
        'detector': 'naabu',
        'discovered_at': '2025-01-01T10:00:00',
        'status': 'open',
        'remediation': 'Close the port if not needed.',
        'risk_score': 75,
        'confidence_level': 'high'
    }
    alert = AlertManagementService._finding_to_alert(finding)
    assert alert['alert_id'] == 'finding_123'
    assert alert['domain'] == 'test.com'
    assert alert['vulnerability_type'] == 'open_port'
    assert alert['severity'] == 'high'

@patch('src.analysis.alert_service.get_ist_now')
def test_create_alert_batch(mock_get_ist_now, alert_service):
    """Test creating a batch of alerts."""
    mock_get_ist_now.return_value = '2025-12-02T12:00:00+05:30'
    
    scan_id = "batch_scan_id"
    alerts_data = [
        {
            'domain': 'test1.com',
            'vulnerability_type': 'open_port',
            'severity': 'high',
            'description': 'Port 80 is open',
            'tool_source': 'naabu'
        },
        {
            'domain': 'test2.com',
            'vulnerability_type': 'subdomain_discovered',
            'severity': 'info',
            'description': 'New subdomain found',
            'tool_source': 'subfinder'
        }
    ]

    findings = alert_service.create_alert_batch(scan_id, alerts_data)

    assert len(findings) == 2
    assert findings[0]['affected_asset'] == 'test1.com'
    assert findings[1]['affected_asset'] == 'test2.com'
    assert findings[0]['risk_score'] == 70
    assert findings[1]['risk_score'] == 10

def test_store_alerts(alert_service, db_manager_mock):
    """Test storing alerts in the database."""
    alerts = [{'id': 'alert1'}, {'id': 'alert2'}]
    alert_service.store_alerts(alerts)
    db_manager_mock.store_findings.assert_called_once_with(alerts)

def test_store_alerts_no_db(alert_service_no_db):
    """Test storing alerts with no db manager."""
    alert_service_no_db.store_alerts([{'id': 'alert1'}])
    # No error should be raised, and a warning should be logged.

def test_store_alerts_db_error(alert_service, db_manager_mock):
    """Test error handling when storing alerts."""
    db_manager_mock.store_findings.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        alert_service.store_alerts([{'id': 'alert1'}])

def test_get_alerts(alert_service, db_manager_mock):
    """Test retrieving alerts."""
    db_manager_mock.get_findings.return_value = {
        'findings': [{'id': 'finding1'}],
        'total_count': 1,
        'has_more': False
    }
    
    with patch.object(AlertManagementService, '_finding_to_alert', return_value={'alert_id': 'alert1'}) as mock_converter:
        result = alert_service.get_alerts(limit=10, offset=0)
        
        assert 'alerts' in result
        assert len(result['alerts']) == 1
        assert result['total_count'] == 1
        mock_converter.assert_called_once_with({'id': 'finding1'})
        db_manager_mock.get_findings.assert_called_once()

def test_get_alerts_no_db(alert_service_no_db):
    """Test retrieving alerts with no db manager."""
    result = alert_service_no_db.get_alerts()
    assert result['findings'] == []
    assert result['total_count'] == 0

def test_get_alerts_db_error(alert_service, db_manager_mock):
    """Test error handling when retrieving alerts."""
    db_manager_mock.get_findings.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        alert_service.get_alerts()

def test_get_alert_by_id(alert_service, db_manager_mock):
    """Test retrieving a single alert by its ID."""
    finding_id = "finding_123"
    db_manager_mock.get_finding_by_id.return_value = {'id': finding_id}
    
    with patch.object(AlertManagementService, '_finding_to_alert', return_value={'alert_id': finding_id}) as mock_converter:
        result = alert_service.get_alert_by_id(finding_id)
        
        assert 'alert' in result
        assert result['alert']['alert_id'] == finding_id
        db_manager_mock.get_finding_by_id.assert_called_once_with(finding_id)
        mock_converter.assert_called_once_with({'id': finding_id})

def test_get_alert_by_id_no_db(alert_service_no_db):
    """Test retrieving an alert by ID with no db manager."""
    with pytest.raises(ValueError, match="No database manager available"):
        alert_service_no_db.get_alert_by_id("any_id")

def test_get_alert_by_id_not_found(alert_service, db_manager_mock):
    """Test retrieving a non-existent alert."""
    db_manager_mock.get_finding_by_id.return_value = None
    with pytest.raises(ValueError, match="Alert not found"):
        alert_service.get_alert_by_id("non_existent_id")

def test_get_alert_by_id_db_error(alert_service, db_manager_mock):
    """Test error handling when retrieving an alert by ID."""
    db_manager_mock.get_finding_by_id.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        alert_service.get_alert_by_id("any_id")

def test_get_alert_statistics(alert_service, db_manager_mock):
    """Test retrieving alert statistics."""
    db_manager_mock.get_findings_statistics.return_value = {
        'total_findings': 10,
        'critical_findings': 1,
        'high_findings': 2,
        'by_status': {'open': 10}
    }
    stats = alert_service.get_alert_statistics()
    assert stats['total'] == 10
    assert stats['by_severity']['critical'] == 1
    assert stats['by_status']['open'] == 10
    db_manager_mock.get_findings_statistics.assert_called_once()

def test_get_alert_statistics_no_db(alert_service_no_db):
    """Test retrieving statistics with no db manager."""
    stats = alert_service_no_db.get_alert_statistics()
    assert stats['total'] == 0
    assert stats['by_severity'] == {}

def test_get_alert_statistics_db_error(alert_service, db_manager_mock):
    """Test error handling when retrieving statistics."""
    db_manager_mock.get_findings_statistics.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        alert_service.get_alert_statistics()

def test_update_alert_status(alert_service, db_manager_mock):
    """Test updating an alert's status."""
    alert_id = "alert_123"
    status = "resolved"
    notes = "This has been fixed."

    db_manager_mock.update_finding_status.return_value = True
    
    success = alert_service.update_alert_status(alert_id, status, notes)
    
    assert success is True
    db_manager_mock.update_finding_status.assert_called_once_with(
        finding_id=alert_id,
        status=status,
        resolution_notes=notes
    )

def test_update_alert_status_no_db(alert_service_no_db):
    """Test updating status with no db manager."""
    success = alert_service_no_db.update_alert_status("any_id", "open")
    assert success is False

def test_update_alert_status_db_error(alert_service, db_manager_mock):
    """Test error handling when updating status."""
    db_manager_mock.update_finding_status.side_effect = Exception("DB error")
    success = alert_service.update_alert_status("any_id", "open")
    assert success is False
