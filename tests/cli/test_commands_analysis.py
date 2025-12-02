
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

@pytest.fixture
def mock_db_manager():
    """Fixture for a mocked SQLModelManager."""
    db = MagicMock()
    db.get_scan_status.return_value = {'status': 'completed'}
    db.get_tool_results.return_value = {'results': []}
    db.get_findings.return_value = {'findings': [], 'total_count': 0}
    db.get_finding_by_id.return_value = None
    db.get_findings_statistics.return_value = {}
    return db

@patch('src.cli.commands_analysis.SQLModelManager')
@patch('src.cli.commands_analysis.AnalysisService')
def test_run_analysis_command(mock_analysis_service, mock_sql_manager, mock_db_manager, capsys):
    """Test the 'run_analysis' command function."""
    mock_sql_manager.return_value = mock_db_manager
    mock_service_instance = MagicMock()
    mock_service_instance.is_enabled.return_value = True
    # Make analyze_scan_results an async mock
    async def async_analyze(*args, **kwargs):
        return {'findings_count': 1, 'statistics': {}}
    mock_service_instance.analyze_scan_results = async_analyze
    mock_analysis_service.return_value = mock_service_instance

    run_analysis_command("scan_123")
    
    captured = capsys.readouterr()
    assert "Running analysis" in captured.out
    assert "Analysis completed" in captured.out

@patch('src.cli.commands_analysis.SQLModelManager')
def test_list_findings_command(mock_sql_manager, mock_db_manager, capsys):
    """Test the 'list_findings' command function."""
    mock_db_manager.get_findings.return_value = {
        'findings': [{'id': '1', 'severity': 'high', 'risk_score': 80, 'finding_type': 'test', 'affected_asset': 'a.com', 'title': 't', 'status': 'open'}],
        'total_count': 1
    }
    mock_sql_manager.return_value = mock_db_manager
    
    list_findings_command()
    
    captured = capsys.readouterr()
    assert "Security Findings" in captured.out

@patch('src.cli.commands_analysis.SQLModelManager')
def test_show_finding_command(mock_sql_manager, mock_db_manager, capsys):
    """Test the 'show_finding' command function."""
    mock_db_manager.get_finding_by_id.return_value = {
        'id': '1', 'scan_id': 's1', 'finding_type': 'test', 'affected_asset': 'a.com',
        'severity': 'high', 'risk_score': 80, 'title': 'Test', 'status': 'open',
        'discovered_at': 't', 'updated_at': 't'
    }
    mock_sql_manager.return_value = mock_db_manager

    show_finding_command("finding_123")

    captured = capsys.readouterr()
    assert "Security Finding Details" in captured.out
    assert "HIGH" in captured.out
@patch('src.cli.commands_analysis.SQLModelManager')
def test_findings_statistics_command(mock_sql_manager, mock_db_manager, capsys):
    """Test the 'findings_statistics' command function."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total_findings': 1, 'average_risk_score': 50, 'critical_findings': 0,
        'high_findings': 1, 'medium_findings': 0, 'low_findings': 0, 'info_findings': 0,
        'open_findings': 1, 'resolved_findings': 0, 'false_positives': 0
    }
    mock_sql_manager.return_value = mock_db_manager

    findings_statistics_command()

    captured = capsys.readouterr()
    assert "Findings Statistics" in captured.out
    assert "Total Findings" in captured.out

@patch('src.cli.commands_analysis.SQLModelManager')
def test_update_finding_status_command(mock_sql_manager, mock_db_manager, capsys):
    """Test the 'update_finding_status' command function."""
    mock_db_manager.update_finding_status.return_value = True
    mock_sql_manager.return_value = mock_db_manager
    
    update_finding_status_command("finding_123", "resolved")

    captured = capsys.readouterr()
    assert "Finding finding_123 status updated to 'resolved'" in captured.out

@patch('src.cli.commands_analysis.SQLModelManager')
def test_update_finding_status_invalid(mock_sql_manager, capsys):
    """Test updating with an invalid status."""
    update_finding_status_command("any", "bad_status")
    captured = capsys.readouterr()
    assert "Invalid status" in captured.err
