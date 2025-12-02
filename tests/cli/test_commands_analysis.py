
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from src.cli.commands_analysis import (
    run_analysis_command,
    list_findings_command,
    show_finding_command,
    findings_statistics_command,
    update_finding_status_command,
)
from src.services.findings_service import FindingNotFound, InvalidFindingStatus


@pytest.fixture
def mock_ctx():
    """Fixture for a mocked CLIContext."""
    ctx = MagicMock()
    # Mock db manager
    ctx.db = MagicMock()
    ctx.db.get_scan_status.return_value = {'status': 'completed'}
    ctx.db.get_tool_results.return_value = {'results': []}
    # Mock findings service
    ctx.findings_service = MagicMock()
    ctx.findings_service.list_findings.return_value = {
        'findings': [],
        'total_count': 0,
        'has_more': False
    }
    ctx.findings_service.get_finding.return_value = None
    ctx.findings_service.get_statistics.return_value = {}
    ctx.findings_service.update_status.return_value = {'success': True}
    return ctx


@patch('src.cli.context.CLIContext')
@patch('src.cli.commands_analysis.AnalysisService')
def test_run_analysis_command(mock_analysis_service, mock_cli_context, mock_ctx, capsys):
    """Test the 'run_analysis' command function."""
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    mock_service_instance = MagicMock()
    mock_service_instance.is_enabled.return_value = True
    mock_service_instance.analyze_scan_results.return_value = {
        'findings_count': 1,
        'statistics': {},
        'findings': []
    }
    mock_analysis_service.return_value = mock_service_instance

    run_analysis_command("scan_123")

    captured = capsys.readouterr()
    assert "Running analysis" in captured.out
    assert "Analysis completed" in captured.out


@patch('src.cli.context.CLIContext')
def test_list_findings_command(mock_cli_context, mock_ctx, capsys):
    """Test the 'list_findings' command function."""
    mock_ctx.findings_service.list_findings.return_value = {
        'findings': [
            {'id': '12345678-1234', 'severity': 'high', 'risk_score': 80,
             'finding_type': 'test', 'affected_asset': 'a.com',
             'title': 'Test Finding', 'status': 'open'}
        ],
        'total_count': 1,
        'has_more': False
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    list_findings_command()

    captured = capsys.readouterr()
    assert "Security Findings" in captured.out


@patch('src.cli.context.CLIContext')
def test_show_finding_command(mock_cli_context, mock_ctx, capsys):
    """Test the 'show_finding' command function."""
    mock_ctx.findings_service.get_finding.return_value = {
        'id': '1', 'scan_id': 's1', 'finding_type': 'test', 'affected_asset': 'a.com',
        'severity': 'high', 'risk_score': 80, 'title': 'Test', 'status': 'open',
        'first_seen': 't', 'last_seen': 't', 'occurrence_count': 1, 'updated_at': 't'
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    show_finding_command("finding_123")

    captured = capsys.readouterr()
    assert "Security Finding Details" in captured.out
    assert "HIGH" in captured.out


@patch('src.cli.context.CLIContext')
def test_findings_statistics_command(mock_cli_context, mock_ctx, capsys):
    """Test the 'findings_statistics' command function."""
    mock_ctx.findings_service.get_statistics.return_value = {
        'total_findings': 1, 'average_risk_score': 50, 'critical_findings': 0,
        'high_findings': 1, 'medium_findings': 0, 'low_findings': 0, 'info_findings': 0,
        'open_findings': 1, 'resolved_findings': 0, 'false_positives': 0
    }
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    findings_statistics_command()

    captured = capsys.readouterr()
    assert "Findings Statistics" in captured.out
    assert "Total Findings" in captured.out


@patch('src.cli.context.CLIContext')
def test_update_finding_status_command(mock_cli_context, mock_ctx, capsys):
    """Test the 'update_finding_status' command function."""
    mock_ctx.findings_service.update_status.return_value = {'success': True}
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    update_finding_status_command("finding_123", "resolved")

    captured = capsys.readouterr()
    assert "Finding finding_123 status updated to 'resolved'" in captured.out


@patch('src.cli.context.CLIContext')
def test_update_finding_status_invalid(mock_cli_context, mock_ctx, capsys):
    """Test updating with an invalid status."""
    mock_ctx.findings_service.update_status.side_effect = InvalidFindingStatus("Invalid status")
    mock_cli_context.return_value.__enter__.return_value = mock_ctx

    # The decorator catches InvalidFindingStatus and exits with code 1
    with pytest.raises(SystemExit) as exc_info:
        update_finding_status_command("any", "bad_status")

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Invalid status" in captured.err
