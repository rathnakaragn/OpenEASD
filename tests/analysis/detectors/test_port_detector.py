
import pytest
from unittest.mock import MagicMock, patch
from src.analysis.detectors.port_detector import PortVulnerabilityDetector

@pytest.fixture
def mock_analysis_config():
    """Fixture for a mocked analysis configuration."""
    config = MagicMock()
    config.get_high_risk_ports.return_value = [21, 3389]
    config.get_medium_risk_ports.return_value = [8080]
    config.get.return_value = {} # Default for port_info
    return config

@patch('src.analysis.detectors.port_detector.get_analysis_config')
def create_detector(mock_get_config, mock_config):
    mock_get_config.return_value = mock_config
    return PortVulnerabilityDetector(config={'enabled': True})

def test_port_detector_init(mock_analysis_config):
    """Test the initialization of the PortVulnerabilityDetector."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        assert detector.is_enabled()
        assert 3306 in detector.database_ports
        assert 21 in detector.high_risk_ports

def test_analyze_no_results(mock_analysis_config):
    """Test analyze method with no naabu results."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        findings = detector.analyze({'naabu_results': []})
        assert len(findings) == 0

def test_analyze_with_various_ports(mock_analysis_config):
    """Test analyze method with a mix of different port types."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        naabu_results = [
            {'port': 3306, 'target_host': 'db.example.com'},        # Database
            {'port': 21, 'target_host': 'ftp.example.com'},         # High-risk & Remote access
            {'port': 8080, 'target_host': 'dev.example.com'},       # Medium-risk
            {'port': 10000, 'target_host': 'admin.example.com'},     # Admin
            {'port': 23, 'target_host': 'telnet.example.com'},      # Remote access (critical)
            {'port': 443, 'target_host': 'secure.example.com'},     # Benign
        ]
        
        findings = detector.analyze({'naabu_results': naabu_results})
        
        assert len(findings) == 6
        
        finding_types = [f['finding_type'] for f in findings]
        assert 'database_port_exposed' in finding_types
        assert 'high_risk_port_exposed' in finding_types
        assert 'medium_risk_port_exposed' in finding_types
        assert 'admin_interface_exposed' in finding_types
        assert finding_types.count('remote_access_exposed') == 2
        
        # Check telnet severity
        telnet_finding = next(f for f in findings if f['port'] == 23)
        assert telnet_finding['severity_hint'] == 'critical'

def test_finding_creation_methods(mock_analysis_config):
    """Test the individual finding creation helper methods."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        
        high_risk = detector._create_high_risk_port_finding(3389, 'host', 'tcp', 'ip')
        assert high_risk['severity_hint'] == 'high'
        assert high_risk['finding_type'] == 'high_risk_port_exposed'

        db = detector._create_database_exposure_finding(5432, 'host', 'tcp', 'ip')
        assert db['severity_hint'] == 'critical'
        assert db['finding_type'] == 'database_port_exposed'

        admin = detector._create_admin_interface_finding(8443, 'host', 'tcp', 'ip')
        assert admin['severity_hint'] == 'high'
        assert admin['finding_type'] == 'admin_interface_exposed'

        remote = detector._create_remote_access_finding(22, 'host', 'tcp', 'ip')
        assert remote['severity_hint'] == 'medium' # SSH is not critical
        assert remote['finding_type'] == 'remote_access_exposed'

        medium_risk = detector._create_medium_risk_port_finding(8080, 'host', 'tcp', 'ip')
        assert medium_risk['severity_hint'] == 'medium'
        assert medium_risk['finding_type'] == 'medium_risk_port_exposed'

def test_get_port_risk_level(mock_analysis_config):
    """Test the get_port_risk_level method."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        assert detector.get_port_risk_level(3306) == 'critical'
        assert detector.get_port_risk_level(21) == 'high'
        assert detector.get_port_risk_level(8080) == 'medium'
        assert detector.get_port_risk_level(443) == 'low'
        assert detector.get_port_risk_level(12345) == 'info'
