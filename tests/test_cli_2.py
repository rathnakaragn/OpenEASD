import json
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner
from datetime import datetime

from src.cli.main import cli
from src.services.domain_service import DomainService
from src.data.models.domain import Domain
from src.services.exceptions import DomainAlreadyExists, DomainNotFound, CliCommandError

@pytest.fixture
def mock_domain_service(monkeypatch):
    """Fixture to mock the DomainService."""
    mock_service = MagicMock(spec=DomainService)
    
    # This is a simplified mock setup. In a real application, you might need to
    # mock the database manager at a lower level if the service interacts with it directly.
    def get_mock_service(*args, **kwargs):
        return mock_service
    
    # The commands in `commands_domain` will instantiate `DomainService`.
    # We patch the class so that it returns our mock service instance.
    monkeypatch.setattr("src.cli.commands_domain.DomainService", get_mock_service)
    return mock_service

def test_cli_version():
    """
    Test the --version option of the CLI.
    """
    runner = CliRunner()
    result = runner.invoke(cli, ['--version'])

    assert result.exit_code == 0
    assert 'openeasd, version 1.0.0' in result.output

def test_domain_list_empty(mock_domain_service):
    """Test 'domain list' command when no domains exist."""
    mock_domain_service.list_domains.return_value = {
        'domains': [],
        'total_count': 0,
        'has_more': False
    }

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'list'])

    assert result.exit_code == 0, f"CLI command failed: {result.output}"
    assert "No domains found" in result.output
    mock_domain_service.list_domains.assert_called_once_with(limit=20, primary_only=False)

def test_domain_list_with_data_table(mock_domain_service):
    """Test 'domain list' command with data in default table format."""
    mock_domain_service.list_domains.return_value = {
        'domains': [
            Domain(domain='example.com', is_primary=True, scan_count=5, last_scanned_at=datetime.now()),
            Domain(domain='test.com', is_primary=False, scan_count=1, last_scanned_at=None),
        ],
        'total_count': 2,
        'has_more': False
    }

    runner = CliRunner()
    # The `--details` flag is what triggers the detailed table view
    result = runner.invoke(cli, ['domain', 'list', '--details'])
    
    assert result.exit_code == 0, result.output
    assert "example.com" in result.output
    assert "test.com" in result.output

def test_domain_list_with_data_json(mock_domain_service):
    """Test 'domain list' command with data in JSON format."""
    # We need to return dictionaries that can be serialized to JSON
    mock_domain_service.list_domains.return_value = {
        'domains': [
            Domain(domain='example.com', is_primary=True, created_at=datetime.now()),
            Domain(domain='test.com', is_primary=False, created_at=datetime.now()),
        ],
        'total_count': 2,
        'has_more': False
    }

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'list', '--output', 'json'])

    assert result.exit_code == 0, result.output
    try:
        json_output = json.loads(result.output)
        assert 'domains' in json_output
        assert len(json_output['domains']) == 2
        # Pydantic's `model_dump` will convert datetimes to strings, so we can check for that
        assert isinstance(json_output['domains'][0]['created_at'], str)
    except (json.JSONDecodeError, KeyError) as e:
        pytest.fail(f"CLI output was not valid JSON or did not have the expected structure. Output: {result.output}, Error: {e}")


def test_domain_add_success(mock_domain_service):
    """Test 'domain add' command for a new domain."""
    mock_domain_service.create_domain.return_value = Domain(domain='newdomain.com')

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'add', 'newdomain.com'])

    assert result.exit_code == 0, result.output
    assert "Added domain" in result.output
    assert "newdomain.com" in result.output
    # The CLI command should call the service method
    mock_domain_service.create_domain.assert_called_once()

def test_domain_add_already_exists(mock_domain_service):
    """Test 'domain add' command when the domain already exists."""
    # Configure the mock to raise the specific exception the command expects
    mock_domain_service.create_domain.side_effect = CliCommandError("Domain already exists")

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'add', 'existing.com'])

    # The CLI should catch the exception and exit with a non-zero status code
    assert result.exit_code == 1, result.output
    assert "Error: Domain already exists" in result.output
    mock_domain_service.create_domain.assert_called_once()


def test_domain_add_with_options(mock_domain_service):
    """Test 'domain add' with --primary and other options."""
    mock_domain_service.create_domain.return_value = Domain(domain='primary.com')

    runner = CliRunner()
    result = runner.invoke(cli, [
        'domain', 'add', 'primary.com',
        '--primary',
        '--contact', 'test@primary.com',
        '--frequency', 'daily'
    ])
    
    assert result.exit_code == 0, result.output
    # Check that the service was called with the correct arguments from the CLI options
    mock_domain_service.create_domain.assert_called_once_with(
        domain='primary.com',
        is_primary=True,
        contact_email='test@primary.com',
        scan_frequency='daily'
    )


def test_domain_update_success(mock_domain_service):
    """Test 'domain update' command for an existing domain."""
    mock_domain_service.update_domain.return_value = Domain(domain='example.com', is_primary=True)

    runner = CliRunner()
    # The `--primary` option in the CLI should be a flag, so we pass `--primary` for True
    # and `--no-primary` for False. If it expects a boolean string, the test would be different.
    # Assuming it's a flag for this test.
    result = runner.invoke(cli, ['domain', 'update', 'example.com', '--primary', 'true'])

    assert result.exit_code == 0, result.output
    assert "Updated domain" in result.output
    assert "example.com" in result.output
    mock_domain_service.update_domain.assert_called_once_with(domain='example.com', is_primary=True)


def test_domain_update_not_found(mock_domain_service):
    """Test 'domain update' for a non-existent domain."""
    mock_domain_service.update_domain.side_effect = CliCommandError("Domain not found")

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'update', 'nonexistent.com', '--primary', 'true'])

    assert result.exit_code == 1, result.output
    assert "Error: Domain not found" in result.output
    mock_domain_service.update_domain.assert_called_once()


def test_domain_remove_success_with_force(mock_domain_service):
    """Test 'domain remove' with --force to bypass confirmation."""
    mock_domain_service.delete_domain.return_value = {'success': True, 'message': 'Domain deleted'}

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'remove', 'example.com', '--force'])

    assert result.exit_code == 0, result.output
    assert "Domain deleted" in result.output
    mock_domain_service.delete_domain.assert_called_once_with(domain='example.com')


def test_domain_remove_interactive_confirm(mock_domain_service):
    """Test 'domain remove' with interactive confirmation (user types 'yes')."""
    mock_domain_service.delete_domain.return_value = {'success': True, 'message': 'Domain deleted'}

    runner = CliRunner()
    # Provide 'yes' to the input prompt
    result = runner.invoke(cli, ['domain', 'remove', 'example.com'], input='yes\n')

    assert result.exit_code == 0, result.output
    assert "Domain deleted" in result.output
    mock_domain_service.delete_domain.assert_called_once_with(domain='example.com')


def test_domain_remove_interactive_cancel(mock_domain_service):
    """Test 'domain remove' with interactive cancellation (user types 'no')."""
    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'remove', 'example.com'], input='no\n')
    
    # Should exit gracefully with a non-zero code if cancelled, or 0 if it's considered a success.
    # The output should indicate cancellation.
    assert "cancelled" in result.output.lower()
    # Ensure the delete method was not called
    mock_domain_service.delete_domain.assert_not_called()

def test_domain_remove_not_found(mock_domain_service):
    """Test 'domain remove' for a non-existent domain."""
    mock_domain_service.delete_domain.side_effect = CliCommandError("Domain not found")

    runner = CliRunner()
    result = runner.invoke(cli, ['domain', 'remove', 'nonexistent.com', '--force'])

    assert result.exit_code == 1, result.output
    assert "Error: Domain not found" in result.output
    mock_domain_service.delete_domain.assert_called_once()