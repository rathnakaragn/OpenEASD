"""
Comprehensive unit tests for ScanService.

Tests business logic for scan management including creation, execution,
status tracking, and results retrieval with proper mocking of database
and tool dependencies.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime
import json

from src.services.scan_service import ScanService
from src.services.scan_workflow_orchestrator import is_web_service
from src.services.exceptions import ScanNotFound, InvalidScanStatus


@pytest.fixture
def mock_db_manager():
    """Mock database manager for testing."""
    db = MagicMock()
    return db


@pytest.fixture
def scan_service(mock_db_manager):
    """ScanService instance with mocked database and disabled analysis."""
    return ScanService(db_manager=mock_db_manager, enable_analysis=False)


@pytest.fixture
def scan_service_with_analysis(mock_db_manager):
    """ScanService instance with analysis enabled."""
    with patch('src.services.scan_workflow_orchestrator.AnalysisService') as mock_analysis_service:
        mock_analysis = MagicMock()
        mock_analysis.is_enabled.return_value = True
        mock_analysis.is_auto_analyze_enabled.return_value = True
        mock_analysis_service.return_value = mock_analysis

        service = ScanService(db_manager=mock_db_manager, enable_analysis=True)
        service._orchestrator.analysis_service = mock_analysis
        return service


# ========================================================================
# is_web_service() Helper Function Tests
# ========================================================================

def test_is_web_service_200_success():
    """Test web service detection with HTTP 200."""
    result = {'status_code': 200, 'server': 'nginx'}
    is_web, confidence = is_web_service(result)
    assert is_web is True
    assert confidence == 0.95


def test_is_web_service_with_server_header():
    """Test web service detection with server header."""
    result = {'status_code': 0, 'server': 'Apache/2.4'}
    is_web, confidence = is_web_service(result)
    assert is_web is True
    assert confidence == 0.85


def test_is_web_service_4xx_error():
    """Test web service detection with 4xx error."""
    result = {'status_code': 404, 'server': ''}
    is_web, confidence = is_web_service(result)
    assert is_web is True
    assert confidence == 0.60


def test_is_web_service_5xx_error():
    """Test web service detection with 5xx error."""
    result = {'status_code': 500}
    is_web, confidence = is_web_service(result)
    assert is_web is True
    assert confidence == 0.60


def test_is_web_service_no_response():
    """Test non-web service detection."""
    result = {'status_code': 0, 'server': ''}
    is_web, confidence = is_web_service(result)
    assert is_web is False
    assert confidence == 0.90


def test_is_web_service_3xx_redirect():
    """Test web service detection with redirect."""
    result = {'status_code': 301}
    is_web, confidence = is_web_service(result)
    # 3xx is in 200-299 check, so it actually returns False
    # The is_web_service function only returns True for 200-299, 4xx-5xx, or server header
    assert is_web is False
    assert confidence == 0.90


# ========================================================================
# ScanService Initialization Tests
# ========================================================================

def test_scan_service_initialization(mock_db_manager):
    """Test ScanService initialization without analysis."""
    service = ScanService(db_manager=mock_db_manager, enable_analysis=False)
    assert service.db == mock_db_manager
    assert service._orchestrator.analysis_service is None


def test_scan_service_with_analysis_enabled(mock_db_manager):
    """Test ScanService initialization with analysis enabled."""
    with patch('src.services.scan_workflow_orchestrator.AnalysisService') as mock_analysis_service:
        mock_analysis = MagicMock()
        mock_analysis.is_enabled.return_value = True
        mock_analysis_service.return_value = mock_analysis

        service = ScanService(db_manager=mock_db_manager, enable_analysis=True)
        assert service._orchestrator.analysis_service is not None


def test_scan_service_analysis_disabled_in_config(mock_db_manager):
    """Test when analysis is disabled in configuration."""
    with patch('src.services.scan_workflow_orchestrator.AnalysisService') as mock_analysis_service:
        mock_analysis = MagicMock()
        mock_analysis.is_enabled.return_value = False
        mock_analysis_service.return_value = mock_analysis

        service = ScanService(db_manager=mock_db_manager, enable_analysis=True)
        assert service._orchestrator.analysis_service is None


def test_scan_service_analysis_init_failure(mock_db_manager):
    """Test when analysis service initialization fails."""
    with patch('src.services.scan_workflow_orchestrator.AnalysisService', side_effect=Exception("Init failed")):
        service = ScanService(db_manager=mock_db_manager, enable_analysis=True)
        assert service._orchestrator.analysis_service is None


# ========================================================================
# format_datetime_iso() Tests (utility function)
# ========================================================================

def test_format_datetime_with_datetime_object():
    """Test datetime formatting with datetime object."""
    from src.utils.timezone import format_datetime_iso
    dt = datetime(2025, 1, 1, 10, 30, 0)
    result = format_datetime_iso(dt)
    assert result == "2025-01-01T10:30:00"


def test_format_datetime_with_string():
    """Test datetime formatting with string."""
    from src.utils.timezone import format_datetime_iso
    result = format_datetime_iso("2025-01-01")
    assert result == "2025-01-01"


def test_format_datetime_with_none():
    """Test datetime formatting with None."""
    from src.utils.timezone import format_datetime_iso
    result = format_datetime_iso(None)
    assert result == ""


# ========================================================================
# _map_service_to_severity() Tests (via orchestrator)
# ========================================================================

def test_map_service_to_severity_critical(scan_service):
    """Test severity mapping for critical services."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("mysql") == "critical"
    assert orch._map_service_to_severity("postgresql") == "critical"
    assert orch._map_service_to_severity("mongodb") == "critical"
    assert orch._map_service_to_severity("redis") == "critical"
    assert orch._map_service_to_severity("elasticsearch") == "critical"


def test_map_service_to_severity_high(scan_service):
    """Test severity mapping for high risk services."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("telnet") == "high"
    assert orch._map_service_to_severity("ftp") == "high"
    assert orch._map_service_to_severity("rsh") == "high"


def test_map_service_to_severity_medium(scan_service):
    """Test severity mapping for medium risk services."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("ssh") == "medium"
    assert orch._map_service_to_severity("smtp") == "medium"


def test_map_service_to_severity_low(scan_service):
    """Test severity mapping for low risk services."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("ntp") == "low"
    assert orch._map_service_to_severity("ntp-time") == "low"


def test_map_service_to_severity_unknown(scan_service):
    """Test severity mapping for unknown services."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("unknown") == "medium"
    assert orch._map_service_to_severity("custom-service") == "medium"


def test_map_service_to_severity_case_insensitive(scan_service):
    """Test that severity mapping is case insensitive."""
    orch = scan_service._orchestrator
    assert orch._map_service_to_severity("MYSQL") == "critical"
    assert orch._map_service_to_severity("Telnet") == "high"
    assert orch._map_service_to_severity("SSH") == "medium"


# ========================================================================
# step1_discover_subdomains() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_subfinder')
@patch('src.services.scan_workflow_orchestrator.get_ist_now')
def test_discover_subdomains_success(mock_ist_now, mock_run_subfinder, scan_service, mock_db_manager):
    """Test successful subdomain discovery."""
    mock_ist_now.return_value = datetime(2025, 1, 1, 10, 0, 0)
    mock_run_subfinder.return_value = ['api.example.com', 'www.example.com']

    result = scan_service._orchestrator.step1_discover_subdomains('example.com', 'scan-123')

    assert result == ['api.example.com', 'www.example.com']
    mock_run_subfinder.assert_called_once_with('example.com', timeout=None)
    mock_db_manager.store_subfinder_results.assert_called_once()


@patch('src.services.scan_workflow_orchestrator.run_subfinder')
def test_discover_subdomains_empty(mock_run_subfinder, scan_service, mock_db_manager):
    """Test subdomain discovery with no results."""
    mock_run_subfinder.return_value = []

    result = scan_service._orchestrator.step1_discover_subdomains('example.com', 'scan-123')

    assert result == []
    mock_db_manager.store_subfinder_results.assert_not_called()


@patch('src.services.scan_workflow_orchestrator.run_subfinder')
def test_discover_subdomains_with_timeout(mock_run_subfinder, scan_service):
    """Test subdomain discovery with timeout."""
    mock_run_subfinder.return_value = ['api.example.com']

    scan_service._orchestrator.step1_discover_subdomains('example.com', 'scan-123', timeout=60)

    mock_run_subfinder.assert_called_once_with('example.com', timeout=60)


# ========================================================================
# step2_resolve_dns() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_dnsx')
@patch('src.services.scan_workflow_orchestrator.is_private_ip')
def test_resolve_dns_success(mock_is_private, mock_run_dnsx, scan_service):
    """Test successful DNS resolution."""
    mock_run_dnsx.return_value = [
        {'host': 'api.example.com', 'a': ['1.2.3.4']},
        {'host': 'www.example.com', 'a': ['5.6.7.8']}
    ]
    mock_is_private.return_value = False

    active, dns_results = scan_service._orchestrator.step2_resolve_dns(['api.example.com', 'www.example.com'])

    assert active == ['api.example.com', 'www.example.com']
    assert len(dns_results) == 2


@patch('src.services.scan_workflow_orchestrator.run_dnsx')
@patch('src.services.scan_workflow_orchestrator.is_private_ip')
def test_resolve_dns_filters_private_ips(mock_is_private, mock_run_dnsx, scan_service):
    """Test that private IPs are filtered out."""
    mock_run_dnsx.return_value = [
        {'host': 'internal.example.com', 'a': ['192.168.1.1']},
        {'host': 'public.example.com', 'a': ['1.2.3.4']}
    ]
    mock_is_private.side_effect = [True, False]

    active, dns_results = scan_service._orchestrator.step2_resolve_dns(['internal.example.com', 'public.example.com'])

    assert active == ['public.example.com']


def test_resolve_dns_empty_input(scan_service):
    """Test DNS resolution with empty input."""
    active, dns_results = scan_service._orchestrator.step2_resolve_dns([])

    assert active == []
    assert dns_results == []


@patch('src.services.scan_workflow_orchestrator.run_dnsx')
def test_resolve_dns_with_timeout(mock_run_dnsx, scan_service):
    """Test DNS resolution with timeout."""
    mock_run_dnsx.return_value = []

    scan_service._orchestrator.step2_resolve_dns(['example.com'], timeout=30)

    mock_run_dnsx.assert_called_once_with(['example.com'], record_types=['a'], timeout=30)


# ========================================================================
# step3_scan_ports() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_naabu')
@patch('src.services.scan_workflow_orchestrator.get_ist_now')
def test_scan_ports_success(mock_ist_now, mock_run_naabu, scan_service, mock_db_manager):
    """Test successful port scanning."""
    mock_ist_now.return_value = datetime(2025, 1, 1, 10, 0, 0)
    mock_run_naabu.return_value = [
        {'subdomain': 'api.example.com', 'port': 443, 'protocol': 'tcp', 'ip': '1.2.3.4'}
    ]

    result = scan_service._orchestrator.step3_scan_ports(['api.example.com'], 'scan-123')

    assert len(result) == 1
    mock_run_naabu.assert_called_once_with(['api.example.com'], timeout=None)
    mock_db_manager.store_naabu_results.assert_called_once()


@patch('src.services.scan_workflow_orchestrator.run_naabu')
def test_scan_ports_empty_input(mock_run_naabu, scan_service):
    """Test port scanning with empty input."""
    result = scan_service._orchestrator.step3_scan_ports([], 'scan-123')

    assert result == []
    mock_run_naabu.assert_not_called()


@patch('src.services.scan_workflow_orchestrator.run_naabu')
def test_scan_ports_no_results(mock_run_naabu, scan_service, mock_db_manager):
    """Test port scanning with no ports found."""
    mock_run_naabu.return_value = []

    result = scan_service._orchestrator.step3_scan_ports(['example.com'], 'scan-123')

    assert result == []
    mock_db_manager.store_naabu_results.assert_not_called()


# ========================================================================
# step5_verify_tls() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_tlsx_parallel')
def test_verify_tls_success(mock_run_tlsx, scan_service):
    """Test successful TLS verification."""
    # Use port 3306 (MySQL) which is NOT in the skip list
    # Port 8080 is skipped as it's a common web service port
    ports_found = [
        {'subdomain': 'db.example.com', 'port': 3306, 'host': 'db.example.com'}
    ]
    mock_run_tlsx.return_value = {'db.example.com:3306': {'tls': False}}

    result = scan_service._orchestrator.step5_verify_tls(ports_found)

    assert 'db.example.com:3306' in result
    mock_run_tlsx.assert_called_once()


@patch('src.services.scan_workflow_orchestrator.run_tlsx_parallel')
def test_verify_tls_skips_encrypted_ports(mock_run_tlsx, scan_service):
    """Test that TLS check is skipped for known encrypted ports."""
    ports_found = [
        {'subdomain': 'api.example.com', 'port': 443},
        {'subdomain': 'ssh.example.com', 'port': 22}
    ]

    result = scan_service._orchestrator.step5_verify_tls(ports_found)

    assert result == {}
    mock_run_tlsx.assert_not_called()


def test_verify_tls_empty_input(scan_service):
    """Test TLS verification with empty input."""
    result = scan_service._orchestrator.step5_verify_tls([])
    assert result == {}


@patch('src.services.scan_workflow_orchestrator.run_tlsx_parallel')
def test_verify_tls_failure(mock_run_tlsx, scan_service):
    """Test TLS verification failure handling."""
    ports_found = [{'subdomain': 'api.example.com', 'port': 3306}]  # Use non-skipped port
    mock_run_tlsx.side_effect = Exception("TLS scan failed")

    result = scan_service._orchestrator.step5_verify_tls(ports_found)

    assert result == {}


# ========================================================================
# step4_probe_http() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_httpx')
def test_probe_http_success(mock_run_httpx, scan_service):
    """Test successful HTTP probing."""
    ports_found = [
        {'host': 'api.example.com', 'port': 443},
        {'host': 'www.example.com', 'port': 80}
    ]
    mock_run_httpx.return_value = [
        {'url': 'https://api.example.com:443', 'status_code': 200},
        {'url': 'http://www.example.com:80', 'status_code': 200}
    ]

    targets, results = scan_service._orchestrator.step4_probe_http(ports_found)

    assert len(targets) == 2
    assert len(results) == 2
    mock_run_httpx.assert_called_once()


def test_probe_http_empty_input(scan_service):
    """Test HTTP probing with empty input."""
    targets, results = scan_service._orchestrator.step4_probe_http([])

    assert targets == []
    assert results == {}


@patch('src.services.scan_workflow_orchestrator.run_httpx')
def test_probe_http_failure(mock_run_httpx, scan_service):
    """Test HTTP probing failure handling."""
    ports_found = [{'host': 'api.example.com', 'port': 443}]
    mock_run_httpx.side_effect = Exception("HTTP probe failed")

    targets, results = scan_service._orchestrator.step4_probe_http(ports_found)

    assert len(targets) == 1
    assert results == {}


# ========================================================================
# step6_detect_services() Tests (via orchestrator)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_nmap_service_detection_parallel')
def test_detect_services_success(mock_run_nmap, scan_service):
    """Test successful service detection."""
    non_web_ports = [('api.example.com', 3306), ('db.example.com', 5432)]
    mock_run_nmap.return_value = {
        'api.example.com:3306': {'status': 'success', 'service': 'mysql', 'version': '5.7'},
        'db.example.com:5432': {'status': 'success', 'service': 'postgresql', 'version': '13'}
    }

    result = scan_service._orchestrator.step6_detect_services(non_web_ports)

    assert len(result) == 2
    mock_run_nmap.assert_called_once_with(non_web_ports, max_workers=5)


def test_detect_services_empty_input(scan_service):
    """Test service detection with empty input."""
    result = scan_service._orchestrator.step6_detect_services([])
    assert result == {}


@patch('src.services.scan_workflow_orchestrator.run_nmap_service_detection_parallel')
def test_detect_services_failure(mock_run_nmap, scan_service):
    """Test service detection failure handling."""
    non_web_ports = [('api.example.com', 3306)]
    mock_run_nmap.side_effect = Exception("Service detection failed")

    result = scan_service._orchestrator.step6_detect_services(non_web_ports)

    assert result == {}


# ========================================================================
# step7_detect_vulnerabilities() Tests (via orchestrator)
# Runs BOTH nuclei AND nmap NSE on all non-web ports (mandatory)
# ========================================================================

@patch('src.services.scan_workflow_orchestrator.run_nmap_vuln_detection_parallel')
@patch('src.services.scan_workflow_orchestrator.run_nuclei_network')
def test_detect_vulnerabilities_success(mock_run_nuclei, mock_run_nmap, scan_service):
    """Test successful vulnerability detection with nuclei + nmap NSE."""
    nmap_service_results = {
        'api.example.com:3306': {'status': 'success', 'service': 'mysql', 'version': '5.7'}
    }
    non_web_ports = [('api.example.com', 3306)]

    # Mock nuclei results
    mock_run_nuclei.return_value = [
        {
            'host': 'api.example.com:3306',
            'template_name': 'MySQL Auth Bypass',
            'severity': 'critical',
            'cve_id': 'CVE-2012-2122'
        }
    ]
    # Mock nmap NSE results
    mock_run_nmap.return_value = {
        'api.example.com:3306': {'vulnerabilities': [{'cve_id': 'CVE-2021-1234', 'severity': 'high'}], 'status': 'success'}
    }

    result = scan_service._orchestrator.step7_detect_vulnerabilities(nmap_service_results, non_web_ports)

    assert 'api.example.com:3306' in result
    assert 'nuclei' in result['api.example.com:3306']
    assert 'nmap' in result['api.example.com:3306']
    assert 'combined' in result['api.example.com:3306']
    mock_run_nuclei.assert_called_once()
    mock_run_nmap.assert_called_once()


def test_detect_vulnerabilities_empty_input(scan_service):
    """Test vulnerability detection with empty non_web_ports."""
    result = scan_service._orchestrator.step7_detect_vulnerabilities({}, [])
    assert result == {}


@patch('src.services.scan_workflow_orchestrator.run_nmap_vuln_detection_parallel')
@patch('src.services.scan_workflow_orchestrator.run_nuclei_network')
def test_detect_vulnerabilities_unknown_services(mock_run_nuclei, mock_run_nmap, scan_service):
    """Test vulnerability detection runs on unknown services with generic scripts."""
    nmap_service_results = {
        'api.example.com:9999': {'status': 'success', 'service': 'unknown'}
    }
    non_web_ports = [('api.example.com', 9999)]

    mock_run_nuclei.return_value = []
    mock_run_nmap.return_value = {
        'api.example.com:9999': {'vulnerabilities': [], 'status': 'no_vulns'}
    }

    result = scan_service._orchestrator.step7_detect_vulnerabilities(nmap_service_results, non_web_ports)

    # Now runs on ALL non-web ports including unknown services
    assert 'api.example.com:9999' in result
    mock_run_nuclei.assert_called_once()
    mock_run_nmap.assert_called_once()


@patch('src.services.scan_workflow_orchestrator.run_nmap_vuln_detection_parallel')
@patch('src.services.scan_workflow_orchestrator.run_nuclei_network')
def test_detect_vulnerabilities_failure(mock_run_nuclei, mock_run_nmap, scan_service):
    """Test vulnerability detection handles failures gracefully."""
    nmap_service_results = {
        'api.example.com:3306': {'status': 'success', 'service': 'mysql', 'version': '5.7'}
    }
    non_web_ports = [('api.example.com', 3306)]

    # Both tools fail
    mock_run_nuclei.side_effect = Exception("Nuclei failed")
    mock_run_nmap.side_effect = Exception("Nmap NSE failed")

    result = scan_service._orchestrator.step7_detect_vulnerabilities(nmap_service_results, non_web_ports)

    # Should still return structure with empty results (graceful failure)
    assert 'api.example.com:3306' in result
    assert result['api.example.com:3306']['nuclei'] == []
    assert result['api.example.com:3306']['combined'] == []


# ========================================================================
# create_scan() Tests
# ========================================================================

def test_create_scan_success(scan_service, mock_db_manager):
    """Test successful scan creation."""
    mock_db_manager.create_scan_session.return_value = 'scan-123'

    result = scan_service.create_scan(
        domains=['example.com', 'test.com'],
        scan_type='passive_subdomain_enum',
        tool_name='subfinder'
    )

    assert result['success'] is True
    assert result['scan_id'] == 'scan-123'
    assert len(result['domains']) == 2


def test_create_scan_with_defaults(scan_service, mock_db_manager):
    """Test scan creation with default values."""
    mock_db_manager.create_scan_session.return_value = 'scan-123'

    result = scan_service.create_scan(domains=['example.com'])

    assert result['scan_type'] == 'passive_subdomain_enum'
    assert result['tool_name'] == 'subfinder'


# ========================================================================
# get_scan_status() Tests
# ========================================================================

def test_get_scan_status_success(scan_service, mock_db_manager):
    """Test successful scan status retrieval."""
    mock_db_manager.get_scan_status.return_value = {
        'scan_id': 'scan-123',
        'status': 'completed',
        'findings_count': 10
    }

    result = scan_service.get_scan_status('scan-123')

    assert result['success'] is True
    assert result['scan']['scan_id'] == 'scan-123'


def test_get_scan_status_not_found(scan_service, mock_db_manager):
    """Test scan status for non-existent scan."""
    mock_db_manager.get_scan_status.return_value = None

    with pytest.raises(ScanNotFound) as exc_info:
        scan_service.get_scan_status('nonexistent')

    assert 'nonexistent' in str(exc_info.value)


# ========================================================================
# get_scan_results() Tests
# ========================================================================

def test_get_scan_results_success(scan_service, mock_db_manager):
    """Test successful scan results retrieval."""
    mock_db_manager.get_scan_status.return_value = {
        'scan_id': 'scan-123',
        'status': 'completed',
        'domains_scanned': ['example.com'],
        'scan_type': 'passive_subdomain_enum',
        'tool_name': 'subfinder',
        'start_time': datetime(2025, 1, 1),
        'end_time': datetime(2025, 1, 1),
        'findings_count': 5
    }
    mock_db_manager.get_tool_results.side_effect = [
        {'results': [{'subdomain': 'api.example.com', 'discovered_at': datetime(2025, 1, 1)}]},
        {'results': [{'target_host': 'api.example.com', 'port': 443, 'protocol': 'tcp', 'ip': '1.2.3.4', 'discovered_at': datetime(2025, 1, 1)}]}
    ]

    result = scan_service.get_scan_results('scan-123')

    assert result['success'] is True
    assert result['scan']['scan_id'] == 'scan-123'
    assert len(result['subdomains']) == 1
    assert len(result['ports']) == 1


def test_get_scan_results_not_found(scan_service, mock_db_manager):
    """Test results for non-existent scan."""
    mock_db_manager.get_scan_status.return_value = None

    with pytest.raises(ScanNotFound):
        scan_service.get_scan_results('nonexistent')


# ========================================================================
# list_scans() Tests
# ========================================================================

def test_list_scans_success(scan_service, mock_db_manager):
    """Test successful scan listing."""
    mock_db_manager.get_scan_history.return_value = {
        'scans': [
            {
                'scan_id': 'scan-123',
                'scan_type': 'passive_subdomain_enum',
                'tool_name': 'subfinder',
                'domains_scanned': ['example.com'],
                'status': 'completed',
                'findings_count': 10,
                'start_time': '2025-01-01',
                'end_time': '2025-01-01'
            }
        ],
        'total_count': 1
    }

    result = scan_service.list_scans(limit=20)

    assert result['success'] is True
    assert len(result['scans']) == 1
    assert result['total_count'] == 1


def test_list_scans_empty(scan_service, mock_db_manager):
    """Test listing scans when none exist."""
    mock_db_manager.get_scan_history.return_value = {
        'scans': [],
        'total_count': 0
    }

    result = scan_service.list_scans()

    assert result['success'] is True
    assert len(result['scans']) == 0


# ========================================================================
# execute_scan_async() Tests
# ========================================================================

def test_execute_scan_async(scan_service, mock_db_manager):
    """Test async scan execution."""
    mock_db_manager.create_scan_session.return_value = 'scan-123'

    result = scan_service.execute_scan_async('example.com')

    assert result['success'] is True
    assert result['scan']['scan_id'] == 'scan-123'
    assert result['scan']['status'] == 'pending'


# ========================================================================
# trigger_analysis() Tests
# ========================================================================

def test_trigger_analysis_success(scan_service, mock_db_manager):
    """Test triggering analysis on completed scan."""
    mock_db_manager.get_scan_status.return_value = {
        'scan_id': 'scan-123',
        'status': 'completed'
    }

    result = scan_service.trigger_analysis('scan-123')

    assert result['success'] is True
    assert result['scan_id'] == 'scan-123'
    assert result['status'] == 'analyzing'


def test_trigger_analysis_scan_not_found(scan_service, mock_db_manager):
    """Test triggering analysis on non-existent scan."""
    mock_db_manager.get_scan_status.return_value = None

    with pytest.raises(ScanNotFound):
        scan_service.trigger_analysis('nonexistent')


def test_trigger_analysis_invalid_status(scan_service, mock_db_manager):
    """Test triggering analysis on scan with invalid status."""
    mock_db_manager.get_scan_status.return_value = {
        'scan_id': 'scan-123',
        'status': 'running'
    }

    with pytest.raises(InvalidScanStatus) as exc_info:
        scan_service.trigger_analysis('scan-123')

    assert "must be completed" in str(exc_info.value)


def test_trigger_analysis_finished_status(scan_service, mock_db_manager):
    """Test triggering analysis on scan with 'finished' status."""
    mock_db_manager.get_scan_status.return_value = {
        'scan_id': 'scan-123',
        'status': 'finished'
    }

    result = scan_service.trigger_analysis('scan-123')

    assert result['success'] is True
