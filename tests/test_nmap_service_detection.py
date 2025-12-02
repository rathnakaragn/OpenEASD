"""
Unit tests for nmap service detection integration.

Tests for:
- run_nmap_service_detection() function
- _parse_nmap_xml() helper function
- Service-to-severity mapping
"""

import pytest
from unittest.mock import patch, MagicMock
from src.tools.runners import run_nmap_service_detection, _parse_nmap_xml
from src.services.scan_service import ScanService


class TestParseNmapXml:
    """Tests for XML parsing helper function."""

    def test_parse_mysql_service(self):
        """Test parsing MySQL service detection."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 3306 example.com" start="1701532800" startstr="Tue Dec  2 12:00:00 2025" version="7.92" xmloutputversion="1.05">
<host starttime="1701532800" endtime="1701532810">
    <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" version="5.7.30-0-log" conf="95" product="MySQL" extrainfo="0-log"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 3306)

        assert result is not None
        assert result['name'] == 'mysql'
        assert result['version'] == '5.7.30-0-log'
        assert result['confidence'] == 95
        assert result['product'] == 'MySQL'
        assert result['extrainfo'] == '0-log'

    def test_parse_ssh_service(self):
        """Test parsing SSH service detection."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" version="OpenSSH 7.4" conf="98" product="OpenSSH"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 22)

        assert result is not None
        assert result['name'] == 'ssh'
        assert 'OpenSSH' in result['version']
        assert result['confidence'] == 98

    def test_parse_postgresql_service(self):
        """Test parsing PostgreSQL service detection."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="5432">
        <state state="open"/>
        <service name="postgresql" version="PostgreSQL 12.2" conf="94" product="PostgreSQL"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 5432)

        assert result is not None
        assert result['name'] == 'postgresql'
        assert 'PostgreSQL' in result['version']
        assert result['confidence'] == 94

    def test_parse_redis_service(self):
        """Test parsing Redis service detection."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" version="Redis 6.0.9" conf="96" product="Redis"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 6379)

        assert result is not None
        assert result['name'] == 'redis'
        assert result['confidence'] == 96

    def test_parse_unknown_service(self):
        """Test parsing unknown service."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="9000">
        <state state="open"/>
        <service name="unknown" conf="30"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 9000)

        assert result is not None
        assert result['name'] == 'unknown'
        assert result['confidence'] == 30

    def test_parse_port_not_found(self):
        """Test parsing when port is not in output."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" conf="100" product="Apache httpd"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 3306)

        assert result is None

    def test_parse_closed_port(self):
        """Test parsing closed port."""
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
    </port>
</host>
</nmaprun>
        '''
        result = _parse_nmap_xml(xml_output, 9999)

        assert result is None

    def test_parse_invalid_xml(self):
        """Test parsing invalid XML."""
        xml_output = "invalid xml <not closed>"
        result = _parse_nmap_xml(xml_output, 3306)

        assert result is None

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        xml_output = ""
        result = _parse_nmap_xml(xml_output, 3306)

        assert result is None


class TestRunNmapServiceDetection:
    """Tests for nmap service detection function."""

    @patch('subprocess.run')
    def test_detect_mysql_success(self, mock_run):
        """Test successful MySQL service detection."""
        mock_xml = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" version="5.7.30-0-log" conf="95" product="MySQL"/>
    </port>
</host>
</nmaprun>
        '''
        mock_run.return_value = MagicMock(stdout=mock_xml)

        result = run_nmap_service_detection('example.com', 3306, timeout=10)

        assert result['service'] == 'mysql'
        assert result['version'] == '5.7.30-0-log'
        assert result['confidence'] == 95
        assert result['status'] == 'success'
        assert result['product'] == 'MySQL'

    @patch('subprocess.run')
    def test_detect_ssh_success(self, mock_run):
        """Test successful SSH service detection."""
        mock_xml = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" version="OpenSSH 7.4" conf="98" product="OpenSSH"/>
    </port>
</host>
</nmaprun>
        '''
        mock_run.return_value = MagicMock(stdout=mock_xml)

        result = run_nmap_service_detection('example.com', 22, timeout=10)

        assert result['service'] == 'ssh'
        assert 'OpenSSH' in result['version']
        assert result['confidence'] == 98
        assert result['status'] == 'success'

    @patch('subprocess.run')
    def test_detect_unknown_service(self, mock_run):
        """Test detection of unknown service."""
        mock_xml = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="9000">
        <state state="open"/>
        <service name="unknown" conf="30"/>
    </port>
</host>
</nmaprun>
        '''
        mock_run.return_value = MagicMock(stdout=mock_xml)

        result = run_nmap_service_detection('example.com', 9000, timeout=10)

        assert result['service'] == 'unknown'
        assert result['confidence'] == 30
        assert result['status'] == 'success'

    @patch('subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Test timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('nmap', 10)

        result = run_nmap_service_detection('example.com', 3306, timeout=10)

        assert result['status'] == 'timeout'
        assert result['service'] == 'unknown'
        assert result['confidence'] == 0

    @patch('subprocess.run')
    def test_no_match_in_output(self, mock_run):
        """Test when port not found in nmap output."""
        mock_xml = '''<?xml version="1.0"?>
<nmaprun>
<host>
    <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" conf="100"/>
    </port>
</host>
</nmaprun>
        '''
        mock_run.return_value = MagicMock(stdout=mock_xml)

        result = run_nmap_service_detection('example.com', 3306, timeout=10)

        assert result['status'] == 'no_match'
        assert result['service'] == 'unknown'

    def test_nmap_not_installed(self):
        """Test error handling when nmap is not installed."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("nmap not found")

            with pytest.raises(Exception) as exc_info:
                run_nmap_service_detection('example.com', 3306, timeout=10)

            assert "Nmap not found" in str(exc_info.value)

    def test_invalid_port(self):
        """Test error handling for invalid port numbers."""
        # Invalid port returns error response instead of raising
        result = run_nmap_service_detection('example.com', 99999, timeout=10)
        assert result['status'] == 'error'
        assert result['service'] == 'unknown'

        result = run_nmap_service_detection('example.com', 0, timeout=10)
        assert result['status'] == 'error'
        assert result['service'] == 'unknown'

    @patch('subprocess.run')
    def test_command_construction(self, mock_run):
        """Test that nmap command is constructed correctly."""
        mock_run.return_value = MagicMock(stdout='<nmaprun><host><port portid="3306"><state state="closed"/></port></host></nmaprun>')

        run_nmap_service_detection('example.com', 3306, timeout=10)

        # Verify nmap command was called with correct parameters
        args = mock_run.call_args[0][0]
        assert 'nmap' in args[0]
        assert '-sV' in args
        assert '--version-all' in args
        assert '-p' in args
        assert '3306' in args
        assert 'example.com' in args


class TestServiceToSeverityMapping:
    """Tests for service-to-severity mapping."""

    def test_mysql_severity(self):
        """Test MySQL maps to CRITICAL."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('mysql') == 'critical'

    def test_postgresql_severity(self):
        """Test PostgreSQL maps to CRITICAL."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('postgresql') == 'critical'

    def test_mongodb_severity(self):
        """Test MongoDB maps to CRITICAL."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('mongodb') == 'critical'

    def test_redis_severity(self):
        """Test Redis maps to CRITICAL."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('redis') == 'critical'

    def test_ssh_severity(self):
        """Test SSH maps to MEDIUM."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('ssh') == 'medium'

    def test_smtp_severity(self):
        """Test SMTP maps to MEDIUM."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('smtp') == 'medium'

    def test_ftp_severity(self):
        """Test FTP maps to HIGH."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('ftp') == 'high'

    def test_telnet_severity(self):
        """Test Telnet maps to HIGH."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('telnet') == 'high'

    def test_ntp_severity(self):
        """Test NTP maps to LOW."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('ntp') == 'low'

    def test_unknown_severity(self):
        """Test unknown service maps to MEDIUM."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('unknown') == 'medium'
        assert service._map_service_to_severity('custom_service') == 'medium'

    def test_case_insensitive_matching(self):
        """Test that service names are matched case-insensitively."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('MySQL') == 'critical'
        assert service._map_service_to_severity('MYSQL') == 'critical'
        assert service._map_service_to_severity('SSH') == 'medium'
        assert service._map_service_to_severity('Ssh') == 'medium'

    def test_whitespace_handling(self):
        """Test that extra whitespace is trimmed."""
        service = ScanService(db_manager=None)
        assert service._map_service_to_severity('  mysql  ') == 'critical'
        assert service._map_service_to_severity('\tssh\n') == 'medium'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
