"""
Unit tests for PortVulnerabilityDetector.

Tests port vulnerability detection including:
- Database port exposure detection
- High-risk service detection
- Admin interface detection
- Remote access service detection
- Finding creation and formatting
"""

import pytest
from src.analysis.detectors.port_detector import PortVulnerabilityDetector


class TestPortVulnerabilityDetector:
    """Test suite for PortVulnerabilityDetector class."""

    @pytest.fixture
    def detector(self):
        """Create PortVulnerabilityDetector instance."""
        return PortVulnerabilityDetector()

    # ============================================================================
    # Basic Configuration Tests
    # ============================================================================

    def test_detector_initialization(self, detector):
        """Test detector initializes with correct configuration."""
        assert detector.is_enabled() == True
        assert detector.get_name() == 'PortVulnerabilityDetector'
        assert len(detector.high_risk_ports) > 0
        assert len(detector.database_ports) > 0
        assert len(detector.admin_ports) > 0
        assert len(detector.remote_access_ports) > 0

    def test_port_info_loaded(self, detector):
        """Test that port information is loaded correctly."""
        assert len(detector.port_info) > 0

        # Check some key ports
        assert 22 in detector.port_info  # SSH
        assert 23 in detector.port_info  # Telnet
        assert 3306 in detector.port_info  # MySQL
        assert 5432 in detector.port_info  # PostgreSQL

        # Check port info structure
        mysql_info = detector.port_info[3306]
        assert 'name' in mysql_info
        assert 'risk' in mysql_info
        assert 'desc' in mysql_info

    # ============================================================================
    # Database Port Detection Tests
    # ============================================================================

    def test_detect_mysql_exposure(self, detector):
        """Test MySQL database exposure detection."""
        scan_data = {
            'naabu_results': [
                {
                    'port': 3306,
                    'target_host': 'db.example.com',
                    'protocol': 'tcp',
                    'ip': '1.2.3.4'
                }
            ]
        }

        findings = detector.analyze(scan_data)

        assert len(findings) >= 1, "Should detect MySQL exposure"

        # Find the database exposure finding
        db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)
        assert db_finding is not None, "Should create database_port_exposed finding"

        # Check finding details
        assert db_finding['port'] == 3306
        assert db_finding['severity_hint'] == 'critical'
        assert db_finding['affected_asset'] == 'db.example.com'
        assert 'MySQL' in db_finding['title']
        assert db_finding['cwe_id'] == 'CWE-200'

    def test_detect_postgresql_exposure(self, detector):
        """Test PostgreSQL database exposure detection."""
        scan_data = {
            'naabu_results': [
                {
                    'port': 5432,
                    'target_host': 'postgres.example.com',
                    'protocol': 'tcp',
                    'ip': '5.6.7.8'
                }
            ]
        }

        findings = detector.analyze(scan_data)
        db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)

        assert db_finding is not None
        assert db_finding['port'] == 5432
        assert db_finding['severity_hint'] == 'critical'
        assert 'PostgreSQL' in db_finding['service_name']

    def test_detect_mongodb_exposure(self, detector):
        """Test MongoDB database exposure detection."""
        scan_data = {
            'naabu_results': [
                {'port': 27017, 'target_host': 'mongo.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)

        assert db_finding is not None
        assert db_finding['port'] == 27017
        assert 'MongoDB' in db_finding['service_name']

    def test_detect_redis_exposure(self, detector):
        """Test Redis exposure detection."""
        scan_data = {
            'naabu_results': [
                {'port': 6379, 'target_host': 'cache.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)

        assert db_finding is not None
        assert db_finding['port'] == 6379
        assert 'Redis' in db_finding['service_name']

    # ============================================================================
    # High-Risk Port Detection Tests
    # ============================================================================

    def test_detect_telnet_exposure(self, detector):
        """Test Telnet service detection (critical risk)."""
        scan_data = {
            'naabu_results': [
                {'port': 23, 'target_host': 'server.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)

        # Should create both remote_access_exposed and high_risk_port_exposed findings
        remote_finding = next((f for f in findings if f['finding_type'] == 'remote_access_exposed'), None)
        assert remote_finding is not None
        assert remote_finding['severity_hint'] == 'critical'
        assert 'Telnet' in remote_finding['title']

    def test_detect_ftp_exposure(self, detector):
        """Test FTP service detection."""
        scan_data = {
            'naabu_results': [
                {'port': 21, 'target_host': 'ftp.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        assert len(findings) >= 1

        # Should detect as both high-risk and remote access
        finding_types = {f['finding_type'] for f in findings}
        assert 'high_risk_port_exposed' in finding_types or 'remote_access_exposed' in finding_types

    def test_detect_rdp_exposure(self, detector):
        """Test RDP service detection."""
        scan_data = {
            'naabu_results': [
                {'port': 3389, 'target_host': 'desktop.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        remote_finding = next((f for f in findings if f['finding_type'] == 'remote_access_exposed'), None)

        assert remote_finding is not None
        assert remote_finding['port'] == 3389
        assert 'RDP' in remote_finding['service_name'] or 'RDP' in remote_finding['title']

    def test_detect_vnc_exposure(self, detector):
        """Test VNC service detection."""
        scan_data = {
            'naabu_results': [
                {'port': 5900, 'target_host': 'vnc.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        assert len(findings) >= 1

        remote_finding = next((f for f in findings if f['finding_type'] == 'remote_access_exposed'), None)
        assert remote_finding is not None

    # ============================================================================
    # Admin Interface Detection Tests
    # ============================================================================

    def test_detect_admin_interface(self, detector):
        """Test admin interface detection."""
        admin_ports = [2082, 2083, 2086, 2087, 8443, 10000]

        for port in admin_ports:
            scan_data = {
                'naabu_results': [
                    {'port': port, 'target_host': 'panel.example.com', 'protocol': 'tcp'}
                ]
            }

            findings = detector.analyze(scan_data)
            admin_finding = next((f for f in findings if f['finding_type'] == 'admin_interface_exposed'), None)

            assert admin_finding is not None, f"Should detect admin interface on port {port}"
            assert admin_finding['port'] == port
            assert admin_finding['severity_hint'] == 'high'
            assert admin_finding['cwe_id'] == 'CWE-425'

    # ============================================================================
    # Medium-Risk Port Detection Tests
    # ============================================================================

    def test_detect_medium_risk_port(self, detector):
        """Test medium-risk port detection."""
        # Assuming 8080 is in medium_risk_ports but not in high_risk_ports
        scan_data = {
            'naabu_results': [
                {'port': 8080, 'target_host': 'app.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)

        # Should have at least one finding
        assert len(findings) >= 1

        # Check if there's a medium risk finding
        medium_finding = next(
            (f for f in findings if f.get('finding_type') == 'medium_risk_port_exposed'),
            None
        )

        if medium_finding:
            assert medium_finding['port'] == 8080
            assert medium_finding['severity_hint'] == 'medium'

    # ============================================================================
    # Multiple Findings Tests
    # ============================================================================

    def test_multiple_ports_same_host(self, detector):
        """Test multiple ports on same host."""
        scan_data = {
            'naabu_results': [
                {'port': 22, 'target_host': 'server.example.com', 'protocol': 'tcp'},
                {'port': 3306, 'target_host': 'server.example.com', 'protocol': 'tcp'},
                {'port': 8080, 'target_host': 'server.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)

        # Should detect multiple findings
        assert len(findings) >= 3, "Should detect findings for each risky port"

        # Check that different finding types are created
        finding_types = {f['finding_type'] for f in findings}
        assert 'database_port_exposed' in finding_types
        assert len(finding_types) >= 2, "Should create different types of findings"

    def test_multiple_hosts(self, detector):
        """Test ports across multiple hosts."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db1.example.com', 'protocol': 'tcp'},
                {'port': 3306, 'target_host': 'db2.example.com', 'protocol': 'tcp'},
                {'port': 5432, 'target_host': 'db3.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)

        # Should detect findings for each host
        assert len(findings) >= 3

        # Check that all hosts are represented
        affected_assets = {f['affected_asset'] for f in findings}
        assert len(affected_assets) == 3

    # ============================================================================
    # Edge Cases and Validation Tests
    # ============================================================================

    def test_empty_scan_data(self, detector):
        """Test with empty scan data."""
        scan_data = {'naabu_results': []}
        findings = detector.analyze(scan_data)
        assert findings == [], "Empty scan should return no findings"

    def test_no_naabu_results(self, detector):
        """Test with missing naabu_results key."""
        scan_data = {}
        findings = detector.analyze(scan_data)
        assert findings == [], "Missing naabu_results should return no findings"

    def test_missing_port_field(self, detector):
        """Test with missing port field in result."""
        scan_data = {
            'naabu_results': [
                {'target_host': 'example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        assert findings == [], "Missing port should be skipped"

    def test_safe_port_no_findings(self, detector):
        """Test that safe ports don't generate findings."""
        safe_ports = [80, 443]  # Common safe ports

        for port in safe_ports:
            scan_data = {
                'naabu_results': [
                    {'port': port, 'target_host': 'web.example.com', 'protocol': 'tcp'}
                ]
            }

            findings = detector.analyze(scan_data)

            # These ports might not be in any risk category
            if port not in detector.high_risk_ports and \
               port not in detector.medium_risk_ports and \
               port not in detector.database_ports and \
               port not in detector.admin_ports and \
               port not in detector.remote_access_ports:
                assert len(findings) == 0, f"Port {port} should not generate findings"

    def test_finding_structure(self, detector):
        """Test that findings have correct structure."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp', 'ip': '1.2.3.4'}
            ]
        }

        findings = detector.analyze(scan_data)
        assert len(findings) >= 1

        finding = findings[0]

        # Check required fields from BaseDetector
        assert 'finding_type' in finding
        assert 'title' in finding
        assert 'description' in finding
        assert 'affected_asset' in finding
        assert 'severity_hint' in finding
        assert 'detector' in finding

        # Check port-specific fields
        assert 'port' in finding
        assert 'protocol' in finding
        assert 'evidence' in finding

        # Check evidence structure
        evidence = finding['evidence']
        assert isinstance(evidence, dict)
        assert 'port' in evidence
        assert 'host' in evidence

    def test_get_port_risk_level(self, detector):
        """Test port risk level determination."""
        # Critical (database)
        assert detector.get_port_risk_level(3306) == 'critical'
        assert detector.get_port_risk_level(5432) == 'critical'

        # High (high-risk ports like Telnet)
        if 23 in detector.high_risk_ports:
            assert detector.get_port_risk_level(23) in ['high', 'critical']

        # Low (standard web ports)
        assert detector.get_port_risk_level(80) == 'low'
        assert detector.get_port_risk_level(443) == 'low'

        # Info (unknown)
        assert detector.get_port_risk_level(99999) == 'info'

    # ============================================================================
    # Remediation and CWE Tests
    # ============================================================================

    def test_findings_include_remediation(self, detector):
        """Test that findings include remediation guidance."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        assert len(findings) >= 1

        finding = findings[0]
        assert 'remediation' in finding
        assert finding['remediation'] is not None
        assert len(finding['remediation']) > 0

    def test_findings_include_cwe(self, detector):
        """Test that findings include CWE identifiers."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)
        db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)

        assert db_finding is not None
        assert 'cwe_id' in db_finding
        assert db_finding['cwe_id'] is not None
        assert db_finding['cwe_id'].startswith('CWE-')

    # ============================================================================
    # Integration with Risk Scoring Tests
    # ============================================================================

    def test_findings_have_severity_hint(self, detector):
        """Test that all findings have severity hints for risk scoring."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},
                {'port': 23, 'target_host': 'server.example.com', 'protocol': 'tcp'},
                {'port': 8080, 'target_host': 'app.example.com', 'protocol': 'tcp'}
            ]
        }

        findings = detector.analyze(scan_data)

        for finding in findings:
            assert 'severity_hint' in finding
            assert finding['severity_hint'] in ['critical', 'high', 'medium', 'low', 'info']

    def test_critical_severity_for_databases(self, detector):
        """Test that database exposures always get critical severity hint."""
        database_ports = [3306, 5432, 27017, 6379]

        for port in database_ports:
            scan_data = {
                'naabu_results': [
                    {'port': port, 'target_host': 'db.example.com', 'protocol': 'tcp'}
                ]
            }

            findings = detector.analyze(scan_data)
            db_finding = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)

            assert db_finding is not None
            assert db_finding['severity_hint'] == 'critical', \
                f"Database port {port} should have critical severity"
