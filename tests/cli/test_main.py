import pytest
from click.testing import CliRunner
from unittest.mock import patch
from src.cli.main import cli

@pytest.fixture
def runner():
    return CliRunner()

@patch('src.cli.main.history_command')
def test_history_command_success(mock_history_command, runner):
    """
    Test the 'history' command to ensure it runs successfully and formats output correctly.
    """
    # Arrange: Mock the service layer function to return a predictable result
    mock_history_command.return_value = {
        'scans': [
            {'scan_id': 'test-scan-123', 'status': 'completed', 'timestamp': '2025-01-01T12:00:00Z', 'total_subdomains': 10},
            {'scan_id': 'test-scan-456', 'status': 'failed', 'timestamp': '2025-01-01T13:00:00Z', 'total_subdomains': 0}
        ],
        'total_count': 2,
        'has_more': False
    }

    # Act: Invoke the CLI command
    result = runner.invoke(cli, ['history', '--output', 'json'])

    # Assert: Check the output and exit code
    assert result.exit_code == 0
    assert '"scan_id": "test-scan-123"' in result.output
    assert '"status": "completed"' in result.output
    assert '"scan_id": "test-scan-456"' in result.output
    assert '"status": "failed"' in result.output
    
    # Verify that the mocked command was called correctly
    mock_history_command.assert_called_once_with(limit=10, output='json')

@patch('src.cli.main.history_command')
def test_history_command_empty(mock_history_command, runner):
    """
    Test the 'history' command when no scans are found.
    """
    # Arrange
    mock_history_command.return_value = {
        'scans': [],
        'total_count': 0,
        'has_more': False
    }

    # Act
    result = runner.invoke(cli, ['history'])

    # Assert
    assert result.exit_code == 0
    # The format_output function might return an empty string or a message.
    # For now, we check that there's no error.
    # A more specific assertion can be added if the output format is known.
    assert "No scan history found" in result.output

@patch('src.cli.main.history_command')
def test_history_command_exception(mock_history_command, runner):
    """
    Test that the 'history' command handles exceptions gracefully.
    """
    # Arrange
    mock_history_command.side_effect = Exception("Database connection failed")

    # Act
    result = runner.invoke(cli, ['history'])

    # Assert
    assert result.exit_code != 0
    assert "Error: Database connection failed" in result.output
    assert isinstance(result.exception, Exception)
