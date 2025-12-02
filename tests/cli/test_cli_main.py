import pytest
from click.testing import CliRunner
from unittest.mock import patch

from src.cli.main import cli

@pytest.fixture
def runner():
    """Fixture for invoking command-line calls."""
    return CliRunner()

def test_cli_no_command(runner):
    """Test that the CLI shows help when no command is given."""
    result = runner.invoke(cli)
    assert result.exit_code == 0
    assert "Usage: cli [OPTIONS] COMMAND [ARGS]..." in result.output

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_success(mock_scan, runner):
    """Test the main 'scan' command on success."""
    mock_scan.return_value = {'success': True, 'total_domains': 1, 'successful_scans': 1, 'scans': []}
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 0
    assert "Batch Scan Summary" in result.output

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_failure(mock_scan, runner):
    """Test the main 'scan' command on failure."""
    mock_scan.return_value = {'success': False, 'message': 'Scan failed'}
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 1
    assert "Error: Scan failed" in result.output

@patch('src.cli.main.view_scans_command')
def test_scans_list_command_error(mock_view, runner):
    """Test the 'scans' command error handling."""
    mock_view.side_effect = Exception("DB Error")
    result = runner.invoke(cli, ['scans'])
    assert result.exit_code == 1
    assert "Error: DB Error" in result.output

@patch('src.cli.main.domain_add_command')
def test_domain_add_command_failure(mock_add, runner):
    """Test the 'domain add' command on failure."""
    mock_add.return_value = {'success': False, 'message': 'Already exists'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com'])
    assert result.exit_code == 1
    assert "Error: Already exists" in result.output

@patch('src.cli.main.domain_list_command')
def test_domain_list_command_failure(mock_list, runner):
    """Test the 'domain list' command on failure."""
    mock_list.return_value = {'success': False, 'message': 'DB error'}
    result = runner.invoke(cli, ['domain', 'list'])
    assert result.exit_code == 1
    assert "Error: DB error" in result.output

@patch('src.cli.main.domain_update_command')
def test_domain_update_command(mock_update, runner):
    """Test the 'domain update' command."""
    mock_update.return_value = {'success': True, 'message': 'Domain updated.'}
    result = runner.invoke(cli, ['domain', 'update', 'example.com', '--primary', 'true'])
    assert result.exit_code == 0
    mock_update.assert_called_with('example.com', True)

@patch('src.cli.main.domain_remove_command')
def test_domain_remove_command_failure(mock_remove, runner):
    """Test the 'domain remove' command on failure."""
    mock_remove.return_value = {'success': False, 'message': 'Not found'}
    result = runner.invoke(cli, ['domain', 'remove', 'example.com'])
    assert result.exit_code == 1
    assert "Error: Not found" in result.output

@patch('src.cli.main.run_analysis_command')
def test_analysis_run_command_error(mock_run_analysis, runner):
    """Test the 'analysis run' command on error."""
    mock_run_analysis.side_effect = Exception("Analysis failed")
    result = runner.invoke(cli, ['analysis', 'run', 'scan_123'])
    assert result.exit_code == 1
    assert "Error: Analysis failed" in result.output

@patch('src.cli.main.list_findings_command')
def test_analysis_findings_command_error(mock_list_findings, runner):
    """Test the 'analysis findings' command on error."""
    mock_list_findings.side_effect = Exception("DB error")
    result = runner.invoke(cli, ['analysis', 'findings'])
    assert result.exit_code == 1
    assert "Error: DB error" in result.output
    
@patch('src.cli.main.show_finding_command')
def test_analysis_show_command(mock_show, runner):
    """Test the 'analysis show' command."""
    result = runner.invoke(cli, ['analysis', 'show', 'finding_123'])
    assert result.exit_code == 0
    mock_show.assert_called_with('finding_123', 'table')

@patch('src.cli.main.findings_statistics_command')
def test_analysis_stats_command(mock_stats, runner):
    """Test the 'analysis stats' command."""
    result = runner.invoke(cli, ['analysis', 'stats'])
    assert result.exit_code == 0
    mock_stats.assert_called()

@patch('src.cli.main.update_finding_status_command')
def test_analysis_update_command(mock_update, runner):
    """Test the 'analysis update' command."""
    mock_update.return_value = {'message': 'Finding updated'}
    result = runner.invoke(cli, ['analysis', 'update', 'finding_123', 'resolved'])
    assert result.exit_code == 0
    mock_update.assert_called_with('finding_123', 'resolved', None)
    assert 'Finding updated' in result.output

# Previous tests for happy paths
@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command(mock_scan, runner):
    mock_scan.return_value = {'success': True, 'total_domains': 1, 'successful_scans': 1, 'scans': [{'status':'success', 'domain': 'example.com'}]}
    result = runner.invoke(cli, ['scan', '--timeout', '10'])
    assert result.exit_code == 0
    mock_scan.assert_called_with({'timeout': 10, 'primary': False})
    assert "Batch Scan Summary" in result.output

@patch('src.cli.main.view_scans_command')
def test_scans_list_command(mock_view, runner):
    mock_view.return_value = {'scans': []}
    result = runner.invoke(cli, ['scans', '--limit', '5'])
    assert result.exit_code == 0
    mock_view.assert_called_with({'limit': 5, 'output': 'table'})

@patch('src.cli.main.results_command')
def test_results_command(mock_results, runner):
    mock_results.return_value = {'subdomains': []}
    result = runner.invoke(cli, ['results', 'scan_123'])
    assert result.exit_code == 0
    mock_results.assert_called_with({'scan_id': 'scan_123', 'output': 'table'})

@patch('src.cli.main.domain_add_command')
def test_domain_add_command(mock_add, runner):
    mock_add.return_value = {'success': True, 'message': 'Domain added.'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com', '--primary'])
    assert result.exit_code == 0
    mock_add.assert_called_with('example.com', True, None, None)
    assert 'Domain added' in result.output

@patch('src.cli.main.domain_list_command')
def test_domain_list_command(mock_list, runner):
    mock_list.return_value = {'success': True, 'domains': [{'domain': 'example.com'}]}
    result = runner.invoke(cli, ['domain', 'list'])
    assert result.exit_code == 0
    mock_list.assert_called()

@patch('src.cli.main.domain_remove_command')
def test_domain_remove_command(mock_remove, runner):
    mock_remove.return_value = {'success': True, 'message': 'Domain removed.', 'deleted': {}}
    result = runner.invoke(cli, ['domain', 'remove', 'example.com', '--force'])
    assert result.exit_code == 0
    mock_remove.assert_called_with('example.com', True)

@patch('src.cli.main.run_analysis_command')
def test_analysis_run_command(mock_run_analysis, runner):
    result = runner.invoke(cli, ['analysis', 'run', 'scan_123'])
    assert result.exit_code == 0
    mock_run_analysis.assert_called_with('scan_123', 'table')

@patch('src.cli.main.list_findings_command')
def test_analysis_findings_command(mock_list_findings, runner):
    result = runner.invoke(cli, ['analysis', 'findings', '--severity', 'high'])
    assert result.exit_code == 0
    mock_list_findings.assert_called()

# Additional comprehensive CLI main module tests

def test_cli_version(runner):
    """Test the CLI version flag."""
    result = runner.invoke(cli, ['--version'])
    assert result.exit_code == 0
    assert "openeasd" in result.output
    assert "1.0.0" in result.output

def test_cli_help(runner):
    """Test the CLI help flag."""
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert "Automated External Attack Surface Detection" in result.output

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_with_primary_flag(mock_scan, runner):
    """Test scan command with primary flag."""
    mock_scan.return_value = {'success': True, 'total_domains': 5, 'successful_scans': 3, 'failed_scans': 2, 'scans': []}
    result = runner.invoke(cli, ['scan', '--primary'])
    assert result.exit_code == 0
    assert "Batch Scan Summary" in result.output
    mock_scan.assert_called_with({'timeout': 300, 'primary': True})

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_with_custom_timeout(mock_scan, runner):
    """Test scan command with custom timeout."""
    mock_scan.return_value = {'success': True, 'total_domains': 1, 'successful_scans': 1, 'failed_scans': 0, 'scans': []}
    result = runner.invoke(cli, ['scan', '--timeout', '600'])
    assert result.exit_code == 0
    mock_scan.assert_called_with({'timeout': 600, 'primary': False})

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_keyboard_interrupt(mock_scan, runner):
    """Test scan command handling keyboard interrupt."""
    mock_scan.side_effect = KeyboardInterrupt()
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 130
    assert "Batch scan cancelled by user" in result.output

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_unexpected_exception(mock_scan, runner):
    """Test scan command handling unexpected exception."""
    mock_scan.side_effect = RuntimeError("Unexpected error")
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 1
    assert "Error: Unexpected error" in result.output

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_with_multiple_successful_scans(mock_scan, runner):
    """Test scan command output with multiple successful scans."""
    scan_results = [
        {'status': 'success', 'domain': 'example.com', 'subdomains': 10, 'active_subdomains': 5, 'open_ports': 3},
        {'status': 'success', 'domain': 'test.com', 'subdomains': 20, 'active_subdomains': 15, 'open_ports': 5},
    ]
    mock_scan.return_value = {
        'success': True,
        'total_domains': 2,
        'successful_scans': 2,
        'failed_scans': 0,
        'scans': scan_results
    }
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 0
    assert "Batch Scan Summary" in result.output
    assert "example.com" in result.output
    assert "test.com" in result.output
    assert "2" in result.output  # total domains

@patch('src.cli.main.batch_scan_subfinder_command')
def test_scan_command_with_failed_scans(mock_scan, runner):
    """Test scan command output with failed scans."""
    scan_results = [
        {'status': 'success', 'domain': 'example.com', 'subdomains': 10, 'active_subdomains': 5, 'open_ports': 3},
        {'status': 'error', 'domain': 'failed.com', 'error': 'Network timeout'},
    ]
    mock_scan.return_value = {
        'success': True,
        'total_domains': 2,
        'successful_scans': 1,
        'failed_scans': 1,
        'scans': scan_results
    }
    result = runner.invoke(cli, ['scan'])
    assert result.exit_code == 0
    assert "failed.com" in result.output
    assert "Network timeout" in result.output

@patch('src.cli.main.view_scans_command')
def test_scans_list_with_json_output(mock_view, runner):
    """Test scans list command with JSON output."""
    mock_view.return_value = {'scans': [{'scan_id': 'scan_123', 'status': 'completed'}]}
    result = runner.invoke(cli, ['scans', '--output', 'json'])
    assert result.exit_code == 0
    mock_view.assert_called_with({'limit': 20, 'output': 'json'})

@patch('src.cli.main.view_scans_command')
def test_scans_list_with_custom_limit(mock_view, runner):
    """Test scans list command with custom limit."""
    mock_view.return_value = {'scans': []}
    result = runner.invoke(cli, ['scans', '--limit', '50'])
    assert result.exit_code == 0
    mock_view.assert_called_with({'limit': 50, 'output': 'table'})

@patch('src.cli.main.results_command')
def test_results_command_with_json_output(mock_results, runner):
    """Test results command with JSON output."""
    mock_results.return_value = {'subdomains': [], 'ports': []}
    result = runner.invoke(cli, ['results', 'scan_123', '--output', 'json'])
    assert result.exit_code == 0
    mock_results.assert_called_with({'scan_id': 'scan_123', 'output': 'json'})

@patch('src.cli.main.results_command')
def test_results_command_with_csv_output(mock_results, runner):
    """Test results command with CSV output."""
    mock_results.return_value = {'subdomains': [], 'ports': []}
    result = runner.invoke(cli, ['results', 'scan_123', '--output', 'csv'])
    assert result.exit_code == 0
    mock_results.assert_called_with({'scan_id': 'scan_123', 'output': 'csv'})

@patch('src.cli.main.results_command')
def test_results_command_with_txt_output(mock_results, runner):
    """Test results command with TXT output."""
    mock_results.return_value = {'subdomains': [], 'ports': []}
    result = runner.invoke(cli, ['results', 'scan_123', '--output', 'txt'])
    assert result.exit_code == 0
    mock_results.assert_called_with({'scan_id': 'scan_123', 'output': 'txt'})

@patch('src.cli.main.results_command')
def test_results_command_error(mock_results, runner):
    """Test results command error handling."""
    mock_results.side_effect = Exception("Scan not found")
    result = runner.invoke(cli, ['results', 'invalid_scan'])
    assert result.exit_code == 1
    assert "Error: Scan not found" in result.output

@patch('src.cli.main.domain_add_command')
def test_domain_add_with_primary_flag(mock_add, runner):
    """Test domain add with primary flag."""
    mock_add.return_value = {'success': True, 'message': 'Domain added.'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com', '--primary'])
    assert result.exit_code == 0
    mock_add.assert_called_with('example.com', True, None, None)

@patch('src.cli.main.domain_add_command')
def test_domain_add_with_contact(mock_add, runner):
    """Test domain add with contact email."""
    mock_add.return_value = {'success': True, 'message': 'Domain added.'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com', '--contact', 'admin@example.com'])
    assert result.exit_code == 0
    mock_add.assert_called_with('example.com', False, 'admin@example.com', None)

@patch('src.cli.main.domain_add_command')
def test_domain_add_with_frequency(mock_add, runner):
    """Test domain add with scan frequency."""
    mock_add.return_value = {'success': True, 'message': 'Domain added.'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com', '--frequency', 'daily'])
    assert result.exit_code == 0
    mock_add.assert_called_with('example.com', False, None, 'daily')

@patch('src.cli.main.domain_add_command')
def test_domain_add_all_options(mock_add, runner):
    """Test domain add with all options."""
    mock_add.return_value = {'success': True, 'message': 'Domain added.'}
    result = runner.invoke(cli, ['domain', 'add', 'example.com', '--primary', '--contact', 'admin@example.com', '--frequency', 'weekly'])
    assert result.exit_code == 0
    mock_add.assert_called_with('example.com', True, 'admin@example.com', 'weekly')

@patch('src.cli.main.domain_list_command')
def test_domain_list_with_limit(mock_list, runner):
    """Test domain list with limit."""
    mock_list.return_value = {'success': True, 'domains': []}
    result = runner.invoke(cli, ['domain', 'list', '--limit', '50'])
    assert result.exit_code == 0
    mock_list.assert_called()

@patch('src.cli.main.domain_list_command')
def test_domain_list_primary_only(mock_list, runner):
    """Test domain list with primary flag."""
    mock_list.return_value = {'success': True, 'domains': []}
    result = runner.invoke(cli, ['domain', 'list', '--primary'])
    assert result.exit_code == 0
    mock_list.assert_called()

@patch('src.cli.main.domain_update_command')
def test_domain_update_all_options(mock_update, runner):
    """Test domain update with all options."""
    mock_update.return_value = {'success': True, 'message': 'Domain updated.'}
    result = runner.invoke(cli, ['domain', 'update', 'example.com', '--primary', 'true'])
    assert result.exit_code == 0
    mock_update.assert_called()

@patch('src.cli.main.domain_remove_command')
def test_domain_remove_with_force(mock_remove, runner):
    """Test domain remove with force flag."""
    mock_remove.return_value = {'success': True, 'message': 'Domain removed.', 'deleted': {}}
    result = runner.invoke(cli, ['domain', 'remove', 'example.com', '--force'])
    assert result.exit_code == 0
    mock_remove.assert_called_with('example.com', True)

@patch('src.cli.main.domain_remove_command')
def test_domain_remove_without_force(mock_remove, runner):
    """Test domain remove without force flag."""
    mock_remove.return_value = {'success': True, 'message': 'Domain removed.', 'deleted': {}}
    result = runner.invoke(cli, ['domain', 'remove', 'example.com'])
    assert result.exit_code == 0
    mock_remove.assert_called_with('example.com', False)

@patch('src.cli.main.run_analysis_command')
def test_analysis_run_with_json_output(mock_run_analysis, runner):
    """Test analysis run with JSON output."""
    mock_run_analysis.return_value = {'findings': []}
    result = runner.invoke(cli, ['analysis', 'run', 'scan_123', '--output', 'json'])
    assert result.exit_code == 0
    mock_run_analysis.assert_called_with('scan_123', 'json')

@patch('src.cli.main.list_findings_command')
def test_analysis_findings_with_json_output(mock_list_findings, runner):
    """Test analysis findings with JSON output."""
    mock_list_findings.return_value = {'findings': [], 'total': 0}
    result = runner.invoke(cli, ['analysis', 'findings', '--output', 'json'])
    assert result.exit_code == 0
    mock_list_findings.assert_called()

@patch('src.cli.main.list_findings_command')
def test_analysis_findings_with_severity_filter(mock_list_findings, runner):
    """Test analysis findings with severity filter."""
    result = runner.invoke(cli, ['analysis', 'findings', '--severity', 'critical'])
    assert result.exit_code == 0
    mock_list_findings.assert_called()

@patch('src.cli.main.show_finding_command')
def test_analysis_show_with_json_output(mock_show, runner):
    """Test analysis show with JSON output."""
    result = runner.invoke(cli, ['analysis', 'show', 'finding_123', '--output', 'json'])
    assert result.exit_code == 0
    mock_show.assert_called_with('finding_123', 'json')

@patch('src.cli.main.findings_statistics_command')
def test_analysis_stats_with_json_output(mock_stats, runner):
    """Test analysis stats with JSON output."""
    mock_stats.return_value = {'total': 0, 'by_severity': {}}
    result = runner.invoke(cli, ['analysis', 'stats', '--output', 'json'])
    assert result.exit_code == 0
    mock_stats.assert_called()

@patch('src.cli.main.update_finding_status_command')
def test_analysis_update_with_notes(mock_update, runner):
    """Test analysis update with notes."""
    mock_update.return_value = {'message': 'Finding updated'}
    result = runner.invoke(cli, ['analysis', 'update', 'finding_123', 'resolved', '--notes', 'Fixed in v1.2'])
    assert result.exit_code == 0
    mock_update.assert_called_with('finding_123', 'resolved', 'Fixed in v1.2')

@patch('src.cli.main.update_finding_status_command')
def test_analysis_update_without_notes(mock_update, runner):
    """Test analysis update without notes."""
    mock_update.return_value = {'message': 'Finding updated'}
    result = runner.invoke(cli, ['analysis', 'update', 'finding_123', 'false_positive'])
    assert result.exit_code == 0
    mock_update.assert_called_with('finding_123', 'false_positive', None)

def test_cli_context_initialization(runner):
    """Test that CLI properly initializes context."""
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    # Context should be properly initialized