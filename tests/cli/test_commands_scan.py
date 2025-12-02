
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.cli.commands_scan import scan_command, batch_scan_subfinder_command


@pytest.fixture
def mock_ctx():
    """Fixture for a mocked CLIContext."""
    ctx = MagicMock()
    ctx.scan_service = MagicMock()
    ctx.domain_service = MagicMock()

    # Default scan service response
    ctx.scan_service.execute_scan.return_value = {
        'success': True,
        'scan_id': 'scan_123',
        'domain': 'example.com',
        'subdomains': ['sub.example.com'],
        'subdomain_count': 1,
        'active_subdomains': ['sub.example.com'],
        'active_count': 1,
        'ports_found': [{'host': 'sub.example.com', 'port': 80, 'protocol': 'tcp', 'ip': '1.1.1.1'}],
        'ports_count': 1,
        'alerts_count': 1,
        'analysis': {'findings_count': 1}
    }
    return ctx


@patch('src.cli.context.CLIContext')
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
def test_scan_command_full_workflow(mock_validate_domain, mock_cli_context, mock_ctx, capsys):
    """Test the full scan workflow of scan_command."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    result = scan_command(args)

    assert result['scan_id'] == 'scan_123'
    assert 'sub.example.com' in result['subdomains']
    assert mock_ctx.scan_service.execute_scan.called
    mock_ctx.scan_service.execute_scan.assert_called_once_with('example.com', timeout=300)


@patch('src.cli.context.CLIContext')
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
def test_scan_command_no_subdomains(mock_validate_domain, mock_cli_context, mock_ctx, capsys):
    """Test scan_command when no subdomains are found."""
    mock_ctx.scan_service.execute_scan.return_value = {
        'success': True,
        'scan_id': 'scan_123',
        'domain': 'example.com',
        'subdomains': [],
        'subdomain_count': 0,
        'active_subdomains': [],
        'active_count': 0,
        'ports_found': [],
        'ports_count': 0,
        'alerts_count': 0
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    result = scan_command(args)

    assert result['scan_id'] == 'scan_123'
    assert len(result['subdomains']) == 0
    assert mock_ctx.scan_service.execute_scan.called


@patch('src.cli.context.CLIContext')
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
def test_scan_command_failure(mock_validate_domain, mock_cli_context, mock_ctx, capsys):
    """Test scan_command error handling."""
    mock_ctx.scan_service.execute_scan.side_effect = Exception("Scan failed")
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    # The decorator catches the exception and calls sys.exit(1)
    with pytest.raises(SystemExit) as exc_info:
        scan_command(args)
    assert exc_info.value.code == 1


@patch('src.cli.context.CLIContext')
def test_batch_scan_subfinder_command_success(mock_cli_context, mock_ctx, capsys):
    """Test batch_scan_subfinder_command success path."""
    mock_domain = MagicMock()
    mock_domain.domain = 'example.com'
    mock_domain.is_primary = True
    mock_ctx.domain_service.list_domains.return_value = {
        'success': True,
        'domains': [mock_domain],
        'total_count': 1,
        'has_more': False
    }
    mock_ctx.scan_service.execute_scan.return_value = {
        'scan_id': 'scan_123',
        'subdomain_count': 5,
        'active_count': 3,
        'ports_count': 2,
        'analysis': {'findings_count': 1}
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)

    assert result['success']
    assert result['total_domains'] == 1
    assert result['successful_scans'] == 1
    assert result['failed_scans'] == 0
    mock_ctx.domain_service.list_domains.assert_called_once()
    mock_ctx.scan_service.execute_scan.assert_called_once_with('example.com', timeout=300)


@patch('src.cli.context.CLIContext')
def test_batch_scan_subfinder_command_no_domains(mock_cli_context, mock_ctx):
    """Test batch_scan_subfinder_command with no domains in DB."""
    mock_ctx.domain_service.list_domains.return_value = {
        'success': True,
        'domains': [],
        'total_count': 0,
        'has_more': False
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)

    assert result['success']
    assert "No domains found" in result['message']
    assert result['total_domains'] == 0


@patch('src.cli.context.CLIContext')
def test_batch_scan_subfinder_command_scan_failure(mock_cli_context, mock_ctx, capsys):
    """Test batch_scan_subfinder_command when an individual scan fails."""
    mock_domain = MagicMock()
    mock_domain.domain = 'example.com'
    mock_domain.is_primary = True
    mock_ctx.domain_service.list_domains.return_value = {
        'success': True,
        'domains': [mock_domain],
        'total_count': 1,
        'has_more': False
    }
    mock_ctx.scan_service.execute_scan.side_effect = Exception("Scan failed")
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)

    assert result['success']
    assert result['total_domains'] == 1
    assert result['successful_scans'] == 0
    assert result['failed_scans'] == 1
    # Verify error was captured in scan results
    assert result['scans'][0]['status'] == 'failed'
    assert 'Scan failed' in result['scans'][0]['error']
