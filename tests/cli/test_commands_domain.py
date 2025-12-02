
import pytest
from unittest.mock import patch, MagicMock

from src.cli.commands_domain import (
    domain_add_command,
    domain_list_command,
    domain_update_command,
    domain_remove_command,
)
from src.services.exceptions import DomainAlreadyExists, InvalidDomainFormat, DomainNotFound


@pytest.fixture
def mock_ctx():
    """Fixture for a mocked CLIContext."""
    ctx = MagicMock()
    ctx.domain_service = MagicMock()
    return ctx


@patch('src.cli.context.CLIContext')
def test_domain_add_command(mock_cli_context, mock_ctx):
    """Test the 'domain_add' command function."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_ctx.domain_service.create_domain.return_value = MagicMock(domain="example.com")

    result = domain_add_command("example.com", True, None, None)
    assert result['success']
    assert "example.com" in result['message']


@patch('src.cli.context.CLIContext')
def test_domain_add_command_exists(mock_cli_context, mock_ctx):
    """Test adding a domain that already exists."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_ctx.domain_service.create_domain.side_effect = DomainAlreadyExists("Domain already exists")

    # The decorator catches DomainAlreadyExists and exits with code 1
    with pytest.raises(SystemExit) as exc_info:
        domain_add_command("example.com", False, None, None)
    assert exc_info.value.code == 1


@patch('src.cli.context.CLIContext')
def test_domain_list_command(mock_cli_context, mock_ctx):
    """Test the 'domain_list' command function."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_domain = MagicMock()
    mock_domain.model_dump.return_value = {'domain': 'example.com'}
    mock_ctx.domain_service.list_domains.return_value = {
        'domains': [mock_domain],
        'total_count': 1,
        'has_more': False
    }

    result = domain_list_command(10, False, False, 'table')
    assert result['success']
    assert len(result['domains']) == 1


@patch('src.cli.context.CLIContext')
def test_domain_update_command(mock_cli_context, mock_ctx):
    """Test the 'domain_update' command function."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_ctx.domain_service.update_domain.return_value = MagicMock(domain="example.com")

    result = domain_update_command("example.com", True)
    assert result['success']


@patch('src.cli.context.CLIContext')
@patch('click.confirm', return_value=True)
def test_domain_remove_command(mock_confirm, mock_cli_context, mock_ctx):
    """Test the 'domain_remove' command function."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_ctx.domain_service.delete_domain.return_value = {'success': True}

    result = domain_remove_command("example.com", False)
    assert result['success']


@patch('src.cli.context.CLIContext')
@patch('click.confirm')
def test_domain_remove_command_force(mock_confirm, mock_cli_context, mock_ctx):
    """Test force removing a domain."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx
    mock_ctx.domain_service.delete_domain.return_value = {'success': True}

    result = domain_remove_command("example.com", True)  # force=True
    assert result['success']
    mock_confirm.assert_not_called()
