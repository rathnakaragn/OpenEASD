
import pytest
from unittest.mock import MagicMock, patch
from src.analysis.detectors.port_detector import PortVulnerabilityDetector

@pytest.fixture
def mock_analysis_config():
    """Fixture for a mocked analysis configuration."""
    config = MagicMock()
    config.get_high_risk_ports.return_value = [21, 23, 3389, 5900, 5432, 3306, 27017, 6379]
    config.get_medium_risk_ports.return_value = [8080, 8443, 9090, 9200]
    config.get_database_ports.return_value = [3306, 5432, 27017, 6379, 1433, 5984, 9042, 7000, 7001]
    config.get_admin_ports.return_value = [2082, 2083, 2086, 2087, 8443, 10000]
    config.get_remote_access_ports.return_value = [21, 22, 23, 3389, 5900, 5901]
    config.get_unencrypted_protocols.return_value = {
        21: {'name': 'FTP', 'encrypted_port': 990, 'encrypted_name': 'FTPS', 'severity': 'high'},
        23: {'name': 'Telnet', 'encrypted_port': 22, 'encrypted_name': 'SSH', 'severity': 'critical'},
        25: {'name': 'SMTP', 'encrypted_port': 465, 'encrypted_name': 'SMTPS', 'severity': 'high'},
        80: {'name': 'HTTP', 'encrypted_port': 443, 'encrypted_name': 'HTTPS', 'severity': 'medium'},
        110: {'name': 'POP3', 'encrypted_port': 995, 'encrypted_name': 'POP3S', 'severity': 'high'},
        143: {'name': 'IMAP', 'encrypted_port': 993, 'encrypted_name': 'IMAPS', 'severity': 'high'},
        389: {'name': 'LDAP', 'encrypted_port': 636, 'encrypted_name': 'LDAPS', 'severity': 'high'},
        5432: {'name': 'PostgreSQL', 'encrypted_port': None, 'encrypted_name': 'PostgreSQL SSL', 'severity': 'critical'},
        3306: {'name': 'MySQL', 'encrypted_port': None, 'encrypted_name': 'MySQL SSL', 'severity': 'critical'},
        27017: {'name': 'MongoDB', 'encrypted_port': None, 'encrypted_name': 'MongoDB TLS', 'severity': 'critical'},
        6379: {'name': 'Redis', 'encrypted_port': None, 'encrypted_name': 'Redis TLS', 'severity': 'critical'},
    }
    config.get.return_value = {}  # Default for port_info
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
            {'port': 3306, 'target_host': 'db.example.com'},        # Database + unencrypted
            {'port': 21, 'target_host': 'ftp.example.com'},         # High-risk + Remote access + unencrypted
            {'port': 8080, 'target_host': 'dev.example.com'},       # Medium-risk
            {'port': 10000, 'target_host': 'admin.example.com'},     # Admin
            {'port': 23, 'target_host': 'telnet.example.com'},      # Remote access (critical) + unencrypted
            {'port': 443, 'target_host': 'secure.example.com'},     # Benign (encrypted)
        ]

        findings = detector.analyze({'naabu_results': naabu_results})

        # Count: 3306(high+db+unenc=3) + 21(high+remote+unenc=3) + 8080(medium=1) + 10000(admin=1) + 23(high+remote+unenc=3) + 443(0) = 11
        assert len(findings) == 11

        finding_types = [f['finding_type'] for f in findings]
        assert 'database_port_exposed' in finding_types
        assert 'high_risk_port_exposed' in finding_types
        assert 'medium_risk_port_exposed' in finding_types
        assert 'admin_interface_exposed' in finding_types
        assert finding_types.count('remote_access_exposed') == 2
        assert 'unencrypted_protocol' in finding_types
        assert finding_types.count('unencrypted_protocol') == 3  # MySQL, FTP, Telnet

        # Check telnet findings (high_risk, remote_access, and unencrypted)
        telnet_findings = [f for f in findings if f['port'] == 23]
        assert len(telnet_findings) == 3  # high_risk + remote_access + unencrypted
        telnet_remote = next(f for f in telnet_findings if f['finding_type'] == 'remote_access_exposed')
        assert telnet_remote['severity_hint'] == 'critical'
        telnet_unenc = next(f for f in telnet_findings if f['finding_type'] == 'unencrypted_protocol')
        assert telnet_unenc['severity_hint'] == 'critical'

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

        # Test unencrypted protocol finding
        unenc_ftp = detector._create_unencrypted_protocol_finding(21, 'host', 'tcp', 'ip')
        assert unenc_ftp['severity_hint'] == 'high'
        assert unenc_ftp['finding_type'] == 'unencrypted_protocol'
        assert unenc_ftp['cwe_id'] == 'CWE-319'
        assert 'encryption' in unenc_ftp['evidence']
        assert unenc_ftp['evidence']['encryption'] == 'none'

        # Test unencrypted protocol finding for critical service (Telnet)
        unenc_telnet = detector._create_unencrypted_protocol_finding(23, 'host', 'tcp', 'ip')
        assert unenc_telnet['severity_hint'] == 'critical'
        assert unenc_telnet['finding_type'] == 'unencrypted_protocol'

def test_get_port_risk_level(mock_analysis_config):
    """Test the get_port_risk_level method."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()
        assert detector.get_port_risk_level(3306) == 'critical'
        assert detector.get_port_risk_level(21) == 'high'
        assert detector.get_port_risk_level(8080) == 'medium'
        assert detector.get_port_risk_level(443) == 'low'
        assert detector.get_port_risk_level(12345) == 'info'


def test_analyze_with_tlsx_results(mock_analysis_config):
    """Test analyze method with tlsx verification results."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()

        naabu_results = [
            {'port': 80, 'target_host': 'http.example.com'},    # Will check tlsx
            {'port': 443, 'target_host': 'https.example.com'},  # TLS enabled
            {'port': 3306, 'target_host': 'db.example.com'},    # No TLS
        ]

        # tlsx results: 80 has no TLS, 443 has TLS, 3306 has no TLS
        tlsx_results = {
            'http.example.com:80': {'tls_enabled': False, 'error': 'TLS handshake failed'},
            'https.example.com:443': {'tls_enabled': True, 'tls_version': 'tls13'},
            'db.example.com:3306': {'tls_enabled': False, 'error': 'No TLS on MySQL'},
        }

        findings = detector.analyze({
            'naabu_results': naabu_results,
            'tlsx_results': tlsx_results
        })

        # Get unencrypted protocol findings
        unenc_findings = [f for f in findings if f['finding_type'] == 'unencrypted_protocol']

        # Should have findings for port 80 and 3306 (verified by tlsx)
        # Port 443 should NOT have unencrypted finding (TLS enabled)
        assert len(unenc_findings) == 2

        # Check port 80 finding
        http_finding = next((f for f in unenc_findings if f['port'] == 80), None)
        assert http_finding is not None
        assert http_finding['evidence']['verified_by_tlsx'] is True
        assert 'Verified by tlsx' in http_finding['title']

        # Check port 3306 finding
        mysql_finding = next((f for f in unenc_findings if f['port'] == 3306), None)
        assert mysql_finding is not None
        assert mysql_finding['evidence']['verified_by_tlsx'] is True

        # Check that port 443 does NOT have unencrypted finding
        https_unenc = [f for f in unenc_findings if f['port'] == 443]
        assert len(https_unenc) == 0


def test_analyze_without_tlsx_falls_back(mock_analysis_config):
    """Test analyze method falls back to port-based detection without tlsx."""
    with patch('src.analysis.detectors.port_detector.get_analysis_config', return_value=mock_analysis_config):
        detector = PortVulnerabilityDetector()

        naabu_results = [
            {'port': 21, 'target_host': 'ftp.example.com'},
        ]

        # No tlsx_results provided
        findings = detector.analyze({'naabu_results': naabu_results})

        # Should have unencrypted protocol finding with unverified note
        unenc_findings = [f for f in findings if f['finding_type'] == 'unencrypted_protocol']
        assert len(unenc_findings) == 1
        assert unenc_findings[0]['evidence']['verified_by_tlsx'] is False
        assert 'unverified' in unenc_findings[0]['title']
