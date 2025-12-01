"""
Tests for the CLI command implementations.

Note: Tool-specific CLI commands (run subfinder, run naabu, etc.) were removed
as users can run tools directly. Tests for tool runners are in test_tools_runners_2.py.
"""
import json
from unittest.mock import MagicMock, patch
import pytest
from datetime import datetime, timedelta
import subprocess
import os
from pathlib import Path


from src.cli.commands_results import view_scans_command, results_command
from src.tools.runners import run_subfinder, run_naabu, run_dnsx, run_httpx
from src.utils.validation import validate_domain, validate_domains


@pytest.fixture
def mock_db_manager(monkeypatch):
    """Fixture to mock the SQLModelManager for commands."""
    mock_instance = MagicMock()
    mock_class = MagicMock(return_value=mock_instance)
    # Patch the class in all relevant command modules that use it
    monkeypatch.setattr("src.cli.commands_results.SQLModelManager", mock_class, raising=False)
    monkeypatch.setattr("src.cli.commands_scan.SQLModelManager", mock_class, raising=False)
    monkeypatch.setattr("src.cli.commands_domain.SQLModelManager", mock_class, raising=False)
    monkeypatch.setattr("src.cli.commands_analysis.SQLModelManager", mock_class, raising=False)
    mock_instance.initialize.return_value = None # Mock the initialize method
    return mock_instance

@pytest.fixture
def mock_config(monkeypatch):
    """Fixture to mock the Config object used in runners."""
    mock_config_instance = MagicMock()
    # Default return values for config.get calls in runners.py
    mock_config_instance.get.side_effect = lambda key, default: {
        'tools.subfinder.path': 'subfinder',
        'subfinder.timeout': 300,
        'naabu.top_ports': 1000,
        'tools.naabu.path': 'naabu',
        'naabu.timeout': 300,
        'workflow.default_timeout': 300,
        'tools.dnsx.path': 'dnsx',
        'tools.httpx.path': 'httpx',
        'httpx.threads': 50,
    }.get(key, default)
    monkeypatch.setattr("src.tools.runners.config", mock_config_instance)
    return mock_config_instance

@pytest.fixture
def mock_pathlib_methods(monkeypatch):
    mock_exists = MagicMock(return_value=True)
    mock_unlink = MagicMock(return_value=None)
    monkeypatch.setattr(Path, 'exists', mock_exists)
    monkeypatch.setattr(Path, 'unlink', mock_unlink)
    return mock_exists, mock_unlink


def test_view_scans_command_empty(mock_db_manager):
    """Test view_scans_command with no data."""
    mock_db_manager.get_scan_history.return_value = {'scans': []}
    result = view_scans_command(args={'limit': 20})
    assert result['type'] == 'scan_list'
    assert result['scans'] == []

def test_view_scans_command_with_data(mock_db_manager):
    """Test view_scans_command with mock data."""
    now = datetime.utcnow()
    mock_scans = {'scans': [{'scan_id': 'scan1', 'scan_type': 'passive', 'tool_name': 'subfinder', 'domains_scanned': ['example.com'], 'status': 'completed', 'findings_count': 150, 'start_time': now, 'end_time': None}]}
    mock_db_manager.get_scan_history.return_value = mock_scans
    result = view_scans_command(args={'limit': 20})
    assert len(result['scans']) == 1
    assert result['scans'][0]['scan_id'] == 'scan1'


# Tests for tool runners (not CLI wrappers)

@patch('subprocess.run')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'subfinder' if 'path' in key else default)
def test_run_subfinder_success(mock_config_get, mock_subprocess_run):
    """Test run_subfinder successfully parses JSON output."""
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "a.example.com"}\n{"host": "b.example.com"}\n'
    mock_subprocess_run.return_value = mock_result
    subdomains = run_subfinder('example.com', timeout=10)
    assert len(subdomains) == 2
    assert 'a.example.com' in subdomains

@patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='subfinder', timeout=10))
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'subfinder' if 'path' in key else default)
def test_run_subfinder_timeout(mock_config_get, mock_subprocess_run):
    """Test run_subfinder with a timeout exception."""
    with pytest.raises(Exception, match="Subfinder timed out after 10 seconds"):
        run_subfinder('example.com', timeout=10)

@patch('subprocess.run', side_effect=FileNotFoundError)
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'subfinder' if 'path' in key else default)
def test_run_subfinder_not_found(mock_config_get, mock_subprocess_run):
    """Test run_subfinder when the binary is not found."""
    with pytest.raises(Exception, match="Subfinder not found"):
        run_subfinder('example.com')

@patch('subprocess.run')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'subfinder' if 'path' in key else default)
def test_run_subfinder_malformed_json(mock_config_get, mock_subprocess_run):
    """Test run_subfinder gracefully handles malformed JSON output."""
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "a.example.com"}\nTHIS IS NOT JSON\n{"host": "b.example.com"}'
    mock_subprocess_run.return_value = mock_result
    subdomains = run_subfinder('example.com', timeout=10)
    assert len(subdomains) == 2
    assert 'a.example.com' in subdomains
    assert 'b.example.com' in subdomains


@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'naabu' if 'path' in key else default)
def test_run_naabu_success(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_naabu successfully parses JSON output."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "a.example.com", "port": 443, "ip": "1.1.1.1", "protocol": "tcp"}\n'
    mock_subprocess_run.return_value = mock_result
    ports = run_naabu(targets=['a.example.com'], top_ports=100, timeout=10)
    assert len(ports) == 1
    assert ports[0]['port'] == 443
    assert ports[0]['ip'] == '1.1.1.1'
    mock_subprocess_run.assert_called_once()
    mock_file.write.assert_called_with('a.example.com\n')
    mock_unlink.assert_called_once()

@patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='naabu', timeout=10))
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'naabu' if 'path' in key else default)
def test_run_naabu_timeout(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_naabu with a timeout exception."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    with pytest.raises(Exception, match="Naabu timed out after 10 seconds"):
        run_naabu(targets=['a.example.com'], top_ports=100, timeout=10)
    mock_unlink.assert_called_once()


@patch('subprocess.run', side_effect=FileNotFoundError)
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'naabu' if 'path' in key else default)
def test_run_naabu_not_found(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_naabu when the binary is not found."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    with pytest.raises(Exception, match="Naabu not found"):
        run_naabu(targets=['a.example.com'], top_ports=100, timeout=10)
    mock_unlink.assert_called_once()


@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'naabu' if 'path' in key else default)
def test_run_naabu_malformed_json(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_naabu gracefully handles malformed JSON output."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "a.example.com", "port": 443}\nTHIS IS NOT JSON\n{"host": "b.example.com", "port": 80, "ip": "1.1.1.2"}'
    mock_subprocess_run.return_value = mock_result
    ports = run_naabu(targets=['a.example.com'], top_ports=100, timeout=10)
    assert len(ports) == 2 # Changed to 2
    assert ports[0]['subdomain'] == 'a.example.com'
    mock_unlink.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'naabu' if 'path' in key else default)
def test_run_naabu_empty_targets(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_naabu returns empty list for empty targets."""
    mock_exists, mock_unlink = mock_pathlib_methods
    ports = run_naabu(targets=[], top_ports=100, timeout=10)
    assert ports == []
    mock_subprocess_run.assert_not_called()
    mock_tempfile.assert_not_called()
    mock_unlink.assert_not_called()


@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_success(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx successfully parses JSON output."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "example.com", "a": ["1.2.3.4"]}\n'
    mock_subprocess_run.return_value = mock_result
    records = run_dnsx(domains=['example.com'], record_types=['a'], timeout=10)
    assert len(records) == 1
    assert records[0]['host'] == 'example.com'
    mock_unlink.assert_called_once()

@patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='dnsx', timeout=10))
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_timeout(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx with a timeout exception."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    with pytest.raises(Exception, match="dnsx timed out after 10 seconds"):
        run_dnsx(domains=['example.com'], record_types=['a'], timeout=10)
    mock_unlink.assert_called_once()

@patch('subprocess.run', side_effect=FileNotFoundError)
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_not_found(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx when the binary is not found."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    with pytest.raises(Exception, match="dnsx not found"):
        run_dnsx(domains=['example.com'], record_types=['a'], timeout=10)
    mock_unlink.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_malformed_json(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx gracefully handles malformed JSON output."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "example.com"}\nINVALID JSON\n{"host": "test.com", "a": ["1.1.1.1"]}'
    mock_subprocess_run.return_value = mock_result
    records = run_dnsx(domains=['example.com'], record_types=['a'], timeout=10)
    assert len(records) == 2 # Two valid JSON objects should be parsed
    assert records[0]['host'] == 'example.com'
    mock_unlink.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_empty_domains(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx returns empty list for empty domains."""
    mock_exists, mock_unlink = mock_pathlib_methods
    records = run_dnsx(domains=[], record_types=['a'], timeout=10)
    assert records == []
    mock_subprocess_run.assert_not_called()
    mock_tempfile.assert_not_called()
    mock_unlink.assert_not_called()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_default_record_types(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx uses A records by default."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "example.com", "a": ["1.2.3.4"]}\n'
    mock_subprocess_run.return_value = mock_result
    records = run_dnsx(domains=['example.com'], record_types=None, timeout=10)
    assert len(records) == 1
    call_args = mock_subprocess_run.call_args[0][0]
    assert '-a' in call_args # Should contain -a flag
    mock_unlink.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'dnsx' if 'path' in key else default)
def test_run_dnsx_complex_records(mock_config_get, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_dnsx handles complex record types (e.g., MX as dict)."""
    mock_exists, mock_unlink = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"host": "example.com", "mx": [{"preference": 10, "host": "mail.example.com"}]}\n'
    mock_subprocess_run.return_value = mock_result
    records = run_dnsx(domains=['example.com'], record_types=['mx'], timeout=10)
    assert len(records) == 1
    assert 'mail.example.com' in records[0]['mx'][0] # Should convert dict to string for display
    mock_unlink.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('os.path.exists', return_value=False)
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'httpx' if 'path' in key else default)
def test_run_httpx_empty_targets(mock_config_get, mock_exists_os, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_httpx returns empty list for empty targets."""
    mock_exists_path, mock_unlink_path = mock_pathlib_methods
    probes = run_httpx(targets=[], threads=50, timeout=10)
    assert probes == []
    mock_subprocess_run.assert_not_called()
    mock_tempfile.assert_not_called()
    mock_unlink_path.assert_not_called()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('os.path.exists', return_value=False)
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'httpx' if 'path' in key else default)
def test_run_httpx_malformed_json(mock_config_get, mock_exists_os, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_httpx gracefully handles malformed JSON output."""
    mock_exists_path, mock_unlink_path = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"url": "https://a.example.com"}\nINVALID JSON\n{"url": "https://b.example.com", "status_code": 200}'
    mock_subprocess_run.return_value = mock_result
    probes = run_httpx(targets=['a.example.com'], threads=50, timeout=10)
    assert len(probes) == 2 # Two valid JSON objects should be parsed
    assert probes[0]['url'] == 'https://a.example.com'
    mock_unlink_path.assert_called_once()

@patch('subprocess.run')
@patch('tempfile.NamedTemporaryFile')
@patch('os.path.exists', return_value=True) # Mock os.path.exists for httpx_cmd detection
@patch('os.path.expanduser', return_value='/mock/home/.pdtm/go/bin/httpx')
@patch('src.tools.runners.config.get', side_effect=lambda key, default: 'httpx' if 'path' in key else default)
def test_run_httpx_pdtm_path_exists(mock_config_get, mock_expanduser, mock_exists_os, mock_tempfile, mock_subprocess_run, mock_pathlib_methods):
    """Test run_httpx uses pdtm_path if it exists."""
    mock_exists_path, mock_unlink_path = mock_pathlib_methods
    mock_file = MagicMock()
    mock_tempfile.return_value.__enter__.return_value = mock_file
    mock_result = MagicMock()
    mock_result.stdout = '{"url": "https://a.example.com", "status_code": 200, "title": "Example"}\n'
    mock_subprocess_run.return_value = mock_result
    probes = run_httpx(targets=['a.example.com'], threads=50, timeout=10)
    assert len(probes) == 1
    assert probes[0]['status_code'] == 200
    # Check that httpx_cmd used the pdtm_path
    mock_subprocess_run.assert_called_once()
    assert mock_subprocess_run.call_args[0][0][0] == '/mock/home/.pdtm/go/bin/httpx'
    mock_unlink_path.assert_called_once()
