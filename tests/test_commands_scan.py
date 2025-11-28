"""
Unit tests for src/cli/commands_scan.py
"""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import subprocess

from src.cli.commands_scan import scan_command, batch_scan_subfinder_command
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.timezone import get_ist_now
from src.utils.validation import validate_domain


@pytest.fixture
def mock_db_manager(monkeypatch):
    """Fixture to mock the SQLModelManager for commands."""
    mock_instance = MagicMock(spec=SQLModelManager)
    # Mock methods called by scan_command and batch_scan_subfinder_command
    mock_instance.initialize.return_value = None
    mock_instance.create_scan_session.return_value = "test_scan_id_123"
    mock_instance.domain_exists.return_value = False
    mock_instance.add_domain.return_value = None
    mock_instance.store_alerts.return_value = None
    mock_instance.update_scan_status.return_value = None
    mock_instance.store_subfinder_results.return_value = None
    mock_instance.store_naabu_results.return_value = None
    mock_instance.get_domains.return_value = {'domains': []} # Default for batch_scan
    mock_instance.close.return_value = None

    mock_class = MagicMock(return_value=mock_instance)
    monkeypatch.setattr("src.cli.commands_scan.SQLModelManager", mock_class)
    return mock_instance

@pytest.fixture
def mock_runners(monkeypatch):
    """Fixture to mock external tool runners."""
    mock_subfinder = MagicMock(return_value=['sub.example.com'])
    mock_dnsx = MagicMock(return_value=[{'host': 'sub.example.com', 'a': ['1.2.3.4']}])
    mock_naabu = MagicMock(return_value=[{'subdomain': 'sub.example.com', 'port': 80, 'protocol': 'tcp'}])

    monkeypatch.setattr("src.cli.commands_scan.run_subfinder", mock_subfinder)
    monkeypatch.setattr("src.cli.commands_scan.run_dnsx", mock_dnsx)
    monkeypatch.setattr("src.cli.commands_scan.run_naabu", mock_naabu)

    return mock_subfinder, mock_dnsx, mock_naabu

@pytest.fixture
def mock_get_ist_now(monkeypatch):
    """Fixture to mock get_ist_now for consistent timestamps."""
    mock_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_func = MagicMock(return_value=mock_time)
    monkeypatch.setattr("src.cli.commands_scan.get_ist_now", mock_func)
    return mock_func

@pytest.fixture
def mock_validate_domain(monkeypatch):
    """Fixture to mock validate_domain."""
    mock_func = MagicMock(side_effect=lambda domain: domain) # Returns domain if valid
    monkeypatch.setattr("src.cli.commands_scan.validate_domain", mock_func)
    return mock_func

@pytest.fixture(autouse=True)
def mock_print(monkeypatch):
    """Mocks print function to prevent console output during tests."""
    mock_print = MagicMock()
    monkeypatch.setattr("builtins.print", mock_print)
    return mock_print


# ============================================================================
# scan_command tests
# ============================================================================

def test_scan_command_success_no_save(mock_runners, mock_validate_domain, mock_print):
    """Test scan_command in success scenario without saving results."""
    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    args = {'domain': 'example.com', 'timeout': 60, 'save': False}
    result = scan_command(args)

    mock_validate_domain.assert_called_once_with('example.com')
    mock_subfinder.assert_called_once_with('example.com', 60)
    mock_dnsx.assert_called_once_with(['sub.example.com'], record_types=['a'], timeout=60)
    mock_naabu.assert_called_once_with(['sub.example.com'], timeout=60)

    assert result['scan_id'] is None
    assert result['domain'] == 'example.com'
    assert 'sub.example.com' in result['subdomains']
    assert 'sub.example.com' in result['active_subdomains']
    assert result['summary']['total_subdomains'] == 1
    assert result['summary']['open_ports'] == 1
    mock_print.assert_any_call("[*] Starting passive subdomain enumeration for: example.com")
    mock_print.assert_any_call("[+] Found 1 subdomains")
    mock_print.assert_any_call("[+] Found 1 active subdomains")
    mock_print.assert_any_call("[+] Found 1 open ports")


@patch('src.analysis.alert_service.AlertManagementService')
def test_scan_command_success_with_save(mock_alert_service_class, mock_db_manager, mock_runners, mock_validate_domain, mock_get_ist_now, mock_print):
    """Test scan_command in success scenario with saving results."""
    # Mock AlertManagementService instance
    mock_alert_service = MagicMock()
    mock_alert_service.create_alert_batch.return_value = []  # Returns findings list
    mock_alert_service.store_alerts.return_value = None
    mock_alert_service_class.return_value = mock_alert_service

    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    args = {'domain': 'example.com', 'timeout': 60, 'save': True}
    result = scan_command(args)

    mock_validate_domain.assert_called_once_with('example.com')
    mock_db_manager.initialize.assert_called_once()
    mock_db_manager.create_scan_session.assert_called_once_with('passive_subdomain_enum', ['example.com'])
    mock_subfinder.assert_called_once_with('example.com', 60)
    mock_dnsx.assert_called_once_with(['sub.example.com'], record_types=['a'], timeout=60)
    mock_naabu.assert_called_once_with(['sub.example.com'], timeout=60)
    mock_db_manager.domain_exists.assert_called_once_with('example.com')
    mock_db_manager.add_domain.assert_called_once_with('example.com', is_primary=True)

    # Verify AlertManagementService was used (not db_manager.store_alerts)
    mock_alert_service_class.assert_called_once_with(mock_db_manager)
    mock_alert_service.create_alert_batch.assert_called_once()
    mock_alert_service.store_alerts.assert_called_once()

    mock_db_manager.update_scan_status.assert_called_once_with(
        "test_scan_id_123", 'completed', end_time=mock_get_ist_now.return_value, findings_count=2
    ) # 1 subdomain alert + 1 port alert
    mock_db_manager.close.assert_called_once()

    assert result['scan_id'] == "test_scan_id_123"
    assert result['domain'] == 'example.com'
    assert result['summary']['total_subdomains'] == 1
    assert result['summary']['open_ports'] == 1


def test_scan_command_tool_failure(mock_db_manager, mock_runners, mock_validate_domain, mock_get_ist_now):
    """Test scan_command when a tool fails."""
    mock_subfinder, _, _ = mock_runners
    mock_subfinder.side_effect = Exception("Subfinder failed")
    args = {'domain': 'example.com', 'save': True}

    with pytest.raises(Exception, match="Subfinder failed"):
        scan_command(args)

    mock_db_manager.initialize.assert_called_once()
    mock_db_manager.create_scan_session.assert_called_once()
    mock_db_manager.update_scan_status.assert_called_once_with(
        "test_scan_id_123", 'failed', end_time=mock_get_ist_now.return_value
    )
    mock_db_manager.close.assert_called_once()


def test_scan_command_invalid_domain(mock_validate_domain):
    """Test scan_command with an invalid domain."""
    mock_validate_domain.side_effect = ValueError("Invalid domain format")
    args = {'domain': 'invalid_domain', 'save': False}

    with pytest.raises(ValueError, match="Invalid domain format"):
        scan_command(args)

    mock_validate_domain.assert_called_once_with('invalid_domain')


def test_scan_command_no_subdomains(mock_runners, mock_validate_domain):
    """Test scan_command when no subdomains are found."""
    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    mock_subfinder.return_value = [] # No subdomains found
    args = {'domain': 'example.com', 'save': False}

    result = scan_command(args)

    mock_subfinder.assert_called_once()
    mock_dnsx.assert_not_called() # No subdomains to resolve
    mock_naabu.assert_not_called() # No active subdomains to scan

    assert result['summary']['total_subdomains'] == 0
    assert result['summary']['active_subdomains'] == 0
    assert result['summary']['open_ports'] == 0


def test_scan_command_no_active_subdomains(mock_runners, mock_validate_domain):
    """Test scan_command when subdomains are found but none are active."""
    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    mock_dnsx.return_value = [] # Subdomains found, but no A records
    args = {'domain': 'example.com', 'save': False}

    result = scan_command(args)

    mock_subfinder.assert_called_once()
    mock_dnsx.assert_called_once()
    mock_naabu.assert_not_called() # No active subdomains to scan

    assert result['summary']['total_subdomains'] == 1
    assert result['summary']['active_subdomains'] == 0
    assert result['summary']['open_ports'] == 0


def test_scan_command_no_open_ports(mock_runners, mock_validate_domain):
    """Test scan_command when active subdomains are found but no open ports."""
    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    mock_naabu.return_value = [] # Active subdomains found, but no open ports
    args = {'domain': 'example.com', 'save': False}

    result = scan_command(args)

    mock_subfinder.assert_called_once()
    mock_dnsx.assert_called_once()
    mock_naabu.assert_called_once()

    assert result['summary']['total_subdomains'] == 1
    assert result['summary']['active_subdomains'] == 1
    assert result['summary']['open_ports'] == 0


# ============================================================================
# batch_scan_subfinder_command tests
# ============================================================================

def test_batch_scan_subfinder_command_no_domains(mock_db_manager, mock_print):
    """Test batch_scan_subfinder_command when no domains are found in DB."""
    mock_db_manager.get_domains.return_value = {'domains': []}
    args = {'primary': False, 'timeout': 60}
    result = batch_scan_subfinder_command(args)

    mock_db_manager.initialize.assert_called_once()
    mock_db_manager.get_domains.assert_called_once_with(limit=1000, primary_only=False)
    mock_db_manager.close.assert_called_once()

    assert result['success'] is True
    assert result['message'] == 'No domains found'
    assert result['total_domains'] == 0
    assert result['successful_scans'] == 0
    assert result['failed_scans'] == 0


def test_batch_scan_subfinder_command_success_single_domain(mock_db_manager, mock_runners, mock_get_ist_now, mock_print):
    """Test batch_scan_subfinder_command with a single successful domain scan."""
    mock_subfinder, mock_dnsx, mock_naabu = mock_runners
    mock_db_manager.get_domains.return_value = {'domains': [{'domain': 'example.com', 'is_primary': True}]}
    args = {'primary': False, 'timeout': 60}
    result = batch_scan_subfinder_command(args)

    mock_db_manager.initialize.assert_called_once()
    mock_db_manager.get_domains.assert_called_once_with(limit=1000, primary_only=False)
    mock_db_manager.create_scan_session.assert_called_once_with(
        scan_type='passive_subdomain_enum', domains=['example.com'], tool_name='subfinder'
    )
    mock_subfinder.assert_called_once_with('example.com', 60)
    mock_dnsx.assert_called_once_with(['sub.example.com'], record_types=['a'], timeout=60)
    mock_naabu.assert_called_once_with(['sub.example.com'], timeout=60)
    mock_db_manager.domain_exists.assert_called_once_with('example.com')
    mock_db_manager.add_domain.assert_called_once_with('example.com', is_primary=True)
    mock_db_manager.store_subfinder_results.assert_called_once()
    mock_db_manager.store_naabu_results.assert_called_once()
    mock_db_manager.store_alerts.assert_called_once()
    mock_db_manager.update_scan_status.assert_called_once_with(
        "test_scan_id_123", 'completed', end_time=mock_get_ist_now.return_value, findings_count=1
    ) # subfinder results count
    mock_db_manager.close.assert_called_once()

    assert result['success'] is True
    assert result['total_domains'] == 1
    assert result['successful_scans'] == 1
    assert result['failed_scans'] == 0
    assert result['scans'][0]['domain'] == 'example.com'
    assert result['scans'][0]['status'] == 'success'
    mock_print.assert_any_call("[*] Found 1 domain(s) to scan")
    mock_print.assert_any_call("[+] Scan completed: example.com")


def test_batch_scan_subfinder_command_mixed_results(mock_db_manager, mock_runners, mock_get_ist_now, mock_print):
    """Test batch_scan_subfinder_command with mixed successful and failed domain scans."""
    mock_subfinder, _, _ = mock_runners
    mock_db_manager.get_domains.return_value = {'domains': [
        {'domain': 'example.com', 'is_primary': True},
        {'domain': 'fail.com', 'is_primary': False}
    ]}
    mock_subfinder.side_effect = [['sub.example.com'], Exception("Subfinder failed for fail.com")]
    args = {'primary': False, 'timeout': 60}
    result = batch_scan_subfinder_command(args)

    mock_db_manager.initialize.assert_called_once()
    assert mock_db_manager.create_scan_session.call_count == 2
    assert mock_subfinder.call_count == 2
    assert mock_db_manager.update_scan_status.call_count == 2 # One completed, one failed
    mock_db_manager.close.assert_called_once()

    assert result['success'] is True
    assert result['total_domains'] == 2
    assert result['successful_scans'] == 1
    assert result['failed_scans'] == 1
    assert result['scans'][0]['domain'] == 'example.com'
    assert result['scans'][0]['status'] == 'success'
    assert result['scans'][1]['domain'] == 'fail.com'
    assert result['scans'][1]['status'] == 'failed'
    mock_print.assert_any_call("[*] Found 2 domain(s) to scan")
    mock_print.assert_any_call("[+] Scan completed: example.com")
    # Due to side_effect for subfinder, the second domain will raise an exception
    # The exception is wrapped by the code, so the message includes the wrapper
    # Check that some failure message was printed for fail.com
    failure_calls = [call for call in mock_print.call_args_list
                     if '[-] Scan failed: fail.com' in str(call)]
    assert len(failure_calls) > 0, "Expected failure message for fail.com"