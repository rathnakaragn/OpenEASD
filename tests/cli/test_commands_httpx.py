from unittest.mock import patch, MagicMock
import pytest
from src.cli.commands_httpx import run_tool_httpx_command

@pytest.fixture
def mock_run_httpx():
    """Mock the run_httpx function from src.tools.runners."""
    with patch('src.cli.commands_httpx.run_httpx') as mock:
        yield mock

def test_run_tool_httpx_command_success(mock_run_httpx):
    """Test successful execution of run_tool_httpx_command."""
    mock_run_httpx.return_value = [
        {"url": "http://example.com", "status_code": 200},
        {"url": "https://test.com", "status_code": 301},
    ]
    args = {
        'targets': ['example.com', 'test.com'],
        'threads': 10,
        'timeout': 5
    }

    result = run_tool_httpx_command(args)

    assert result['success'] is True
    assert result['tool'] == 'httpx'
    assert result['probe_count'] == 2
    assert len(result['probes']) == 2
    mock_run_httpx.assert_called_once_with(args['targets'], threads=args['threads'], timeout=args['timeout'])

def test_run_tool_httpx_command_no_probes(mock_run_httpx):
    """Test execution when no HTTP services are found."""
    mock_run_httpx.return_value = []
    args = {
        'targets': ['example.com'],
        'threads': 10,
        'timeout': 5
    }

    result = run_tool_httpx_command(args)

    assert result['success'] is True
    assert result['message'] == 'No HTTP services found'
    assert result['probe_count'] == 0
    assert len(result['probes']) == 0
    mock_run_httpx.assert_called_once_with(args['targets'], threads=args['threads'], timeout=args['timeout'])

def test_run_tool_httpx_command_exception(mock_run_httpx):
    """Test execution when an exception occurs."""
    mock_run_httpx.side_effect = Exception("Httpx tool failed")
    args = {
        'targets': ['example.com'],
        'threads': 10,
        'timeout': 5
    }

    result = run_tool_httpx_command(args)

    assert result['success'] is False
    assert result['tool'] == 'httpx'
    assert "Httpx tool failed" in result['error']
    mock_run_httpx.assert_called_once_with(args['targets'], threads=args['threads'], timeout=args['timeout'])

def test_run_tool_httpx_command_single_target_string(mock_run_httpx):
    """Test with a single target provided as a string instead of a list."""
    mock_run_httpx.return_value = [{"url": "http://single.com", "status_code": 200}]
    args = {
        'targets': 'single.com',
        'threads': 10,
        'timeout': 5
    }

    result = run_tool_httpx_command(args)

    assert result['success'] is True
    assert result['probe_count'] == 1
    mock_run_httpx.assert_called_once_with(['single.com'], threads=args['threads'], timeout=args['timeout'])

