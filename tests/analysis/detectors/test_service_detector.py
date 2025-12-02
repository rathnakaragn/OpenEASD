
import pytest
from unittest.mock import MagicMock, patch
from src.analysis.detectors.service_detector import ServiceVulnerabilityDetector


@pytest.fixture
def mock_analysis_config():
    """Fixture for a mocked analysis configuration."""
    config = MagicMock()

    # Configure getter methods for service detector (consistent with port_detector pattern)
    config.get_critical_services.return_value = [
        'mysql', 'postgresql', 'mongodb', 'redis', 'memcached',
        'elasticsearch', 'cassandra', 'couchdb', 'mariadb', 'oracle', 'mssql'
    ]
    config.get_high_risk_services.return_value = [
        'telnet', 'ftp', 'rsh', 'rlogin', 'vnc', 'rdp', 'smb', 'netbios'
    ]
    config.get_medium_risk_services.return_value = [
        'ssh', 'smtp', 'dns', 'snmp', 'ldap', 'nfs', 'rpc'
    ]

    # Keep get method for any other config lookups
    config.get.return_value = {}
    return config


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_service_detector_init(mock_get_config, mock_analysis_config):
    """Test the initialization of the ServiceVulnerabilityDetector."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()
    assert detector.is_enabled()
    assert 'mysql' in detector.critical_services
    assert 'telnet' in detector.high_risk_services
    assert 'ssh' in detector.medium_risk_services


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_no_results(mock_get_config, mock_analysis_config):
    """Test analyze method with no nmap results."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()
    findings = detector.analyze({'nmap_service_results': {}})
    assert len(findings) == 0


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_with_critical_service(mock_get_config, mock_analysis_config):
    """Test analyze method with a critical service (database)."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'db.example.com:3306': {
            'status': 'success',
            'service': 'mysql',
            'version': '8.0.32',
            'product': 'MySQL',
            'confidence': 100
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})

    assert len(findings) >= 1
    critical_finding = next(f for f in findings if f['finding_type'] == 'critical_service_exposed')
    assert critical_finding['severity_hint'] == 'critical'
    assert critical_finding['port'] == 3306
    assert critical_finding['affected_asset'] == 'db.example.com'
    assert 'MySQL' in critical_finding['title']


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_with_high_risk_service(mock_get_config, mock_analysis_config):
    """Test analyze method with a high-risk service (telnet)."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'old.example.com:23': {
            'status': 'success',
            'service': 'telnet',
            'version': '',
            'product': 'Linux telnetd',
            'confidence': 95
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})

    assert len(findings) >= 1
    high_risk_finding = next(f for f in findings if f['finding_type'] == 'high_risk_service_exposed')
    assert high_risk_finding['severity_hint'] == 'high'
    assert high_risk_finding['port'] == 23
    assert 'telnet' in high_risk_finding['service_name'].lower()


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_with_medium_risk_service(mock_get_config, mock_analysis_config):
    """Test analyze method with a medium-risk service (ssh)."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'server.example.com:22': {
            'status': 'success',
            'service': 'ssh',
            'version': '8.9p1',
            'product': 'OpenSSH',
            'confidence': 100
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})

    assert len(findings) >= 1
    medium_finding = next(f for f in findings if f['finding_type'] == 'service_exposed')
    assert medium_finding['severity_hint'] == 'medium'
    assert medium_finding['port'] == 22


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_with_outdated_version(mock_get_config, mock_analysis_config):
    """Test analyze method detects outdated service versions."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'old.example.com:22': {
            'status': 'success',
            'service': 'openssh',
            'version': '5.3',
            'product': 'OpenSSH',
            'confidence': 100
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})

    # Should detect outdated version
    outdated_findings = [f for f in findings if f['finding_type'] == 'outdated_service_version']
    assert len(outdated_findings) == 1
    assert outdated_findings[0]['severity_hint'] == 'high'
    assert '5.3' in outdated_findings[0]['title']


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_skips_failed_detection(mock_get_config, mock_analysis_config):
    """Test analyze method skips services with failed detection status."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'server.example.com:12345': {
            'status': 'failed',
            'service': 'unknown',
            'version': '',
            'product': '',
            'confidence': 0
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})
    assert len(findings) == 0


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_analyze_skips_unknown_low_confidence(mock_get_config, mock_analysis_config):
    """Test analyze method skips unknown services with low confidence."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'server.example.com:9999': {
            'status': 'success',
            'service': 'unknown',
            'version': '',
            'product': '',
            'confidence': 30
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})
    assert len(findings) == 0


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_get_service_risk_level(mock_get_config, mock_analysis_config):
    """Test the get_service_risk_level method."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    assert detector.get_service_risk_level('mysql') == 'critical'
    assert detector.get_service_risk_level('postgresql') == 'critical'
    assert detector.get_service_risk_level('redis') == 'critical'
    assert detector.get_service_risk_level('telnet') == 'high'
    assert detector.get_service_risk_level('ftp') == 'high'
    assert detector.get_service_risk_level('vnc') == 'high'
    assert detector.get_service_risk_level('ssh') == 'medium'
    assert detector.get_service_risk_level('smtp') == 'medium'
    assert detector.get_service_risk_level('http') == 'low'
    assert detector.get_service_risk_level('https') == 'low'
    assert detector.get_service_risk_level('custom-app') == 'info'


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_multiple_services_analysis(mock_get_config, mock_analysis_config):
    """Test analyze method with multiple services."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'db.example.com:3306': {
            'status': 'success',
            'service': 'mysql',
            'version': '8.0.32',
            'product': 'MySQL',
            'confidence': 100
        },
        'web.example.com:22': {
            'status': 'success',
            'service': 'ssh',
            'version': '8.9p1',
            'product': 'OpenSSH',
            'confidence': 100
        },
        'legacy.example.com:23': {
            'status': 'success',
            'service': 'telnet',
            'version': '',
            'product': '',
            'confidence': 90
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})

    # Should have at least 3 findings (one per service)
    assert len(findings) >= 3

    finding_types = [f['finding_type'] for f in findings]
    assert 'critical_service_exposed' in finding_types  # MySQL
    assert 'high_risk_service_exposed' in finding_types  # Telnet
    assert 'service_exposed' in finding_types  # SSH


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_finding_has_required_fields(mock_get_config, mock_analysis_config):
    """Test that findings have all required fields."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    nmap_results = {
        'db.example.com:5432': {
            'status': 'success',
            'service': 'postgresql',
            'version': '15.2',
            'product': 'PostgreSQL',
            'confidence': 100
        }
    }

    findings = detector.analyze({'nmap_service_results': nmap_results})
    assert len(findings) >= 1

    finding = findings[0]

    # Check required fields
    required_fields = [
        'finding_type', 'title', 'description', 'affected_asset',
        'severity_hint', 'port', 'protocol', 'service_name',
        'evidence', 'remediation', 'cwe_id'
    ]

    for field in required_fields:
        assert field in finding, f"Missing required field: {field}"

    # Check evidence structure
    assert 'port' in finding['evidence']
    assert 'host' in finding['evidence']
    assert 'service' in finding['evidence']


@patch('src.analysis.detectors.service_detector.get_analysis_config')
def test_service_info_metadata(mock_get_config, mock_analysis_config):
    """Test that service_info provides proper metadata."""
    mock_get_config.return_value = mock_analysis_config
    detector = ServiceVulnerabilityDetector()

    # Check service_info for known services
    assert 'mysql' in detector.service_info
    assert detector.service_info['mysql']['type'] == 'database'
    assert 'remediation' in detector.service_info['mysql']

    assert 'telnet' in detector.service_info
    assert detector.service_info['telnet']['type'] == 'remote_access'
    assert detector.service_info['telnet']['cwe_id'] == 'CWE-319'

