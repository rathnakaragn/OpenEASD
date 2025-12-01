"""
Unit tests for src/cli/commands_analysis.py
"""
import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone
import asyncio
import click

from src.cli.commands_analysis import (
    run_analysis_command,
    list_findings_command,
    show_finding_command,
    findings_statistics_command,
    update_finding_status_command
)
from src.data.database.sqlmodel_manager import SQLModelManager
from src.analysis.analysis_service import AnalysisService
from src.cli.formatters import format_table, format_json # Import actual formatters
from src.utils.timezone import get_ist_now


@pytest.fixture
def mock_db_manager(monkeypatch):
    """Fixture to mock the SQLModelManager for analysis commands."""
    mock_instance = MagicMock(spec=SQLModelManager)
    mock_instance.initialize.return_value = None
    mock_instance.close.return_value = None
    mock_instance.get_scan_status.return_value = {
        'scan_id': 'test_scan_id_123',
        'status': 'completed',
        'start_time': datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        'end_time': datetime(2025, 1, 1, 11, 0, 0, tzinfo=timezone.utc),
        'tool_name': 'subfinder',
        'domains_scanned': ['example.com']
    }
    def get_tool_results_side_effect(scan_id, tool_name, limit=100, offset=0):
        if tool_name == 'subfinder':
            return {'results': [{'subdomain': 'sub.example.com'}], 'total_count': 1, 'has_more': False}
        elif tool_name == 'naabu':
            return {'results': [{'port': 80, 'subdomain': 'sub.example.com'}], 'total_count': 1, 'has_more': False}
        return {'results': [], 'total_count': 0, 'has_more': False}
    mock_instance.get_tool_results = MagicMock(side_effect=get_tool_results_side_effect)
    mock_instance.get_findings.return_value = {'findings': [], 'total_count': 0}
    mock_instance.get_finding_by_id.return_value = None
    mock_instance.get_findings_statistics.return_value = {
        'total_findings': 0,
        'critical_findings': 0, 'high_findings': 0, 'medium_findings': 0, 'low_findings': 0, 'info_findings': 0,
        'open_findings': 0, 'resolved_findings': 0, 'false_positives': 0,
        'average_risk_score': 0
    }
    mock_instance.update_finding_status.return_value = True

    mock_class = MagicMock(return_value=mock_instance)
    monkeypatch.setattr("src.cli.commands_analysis.SQLModelManager", mock_class)
    return mock_instance

@pytest.fixture
def mock_analysis_service(monkeypatch):
    """Fixture to mock the AnalysisService."""
    mock_instance = MagicMock(spec=AnalysisService)
    mock_instance.is_enabled.return_value = True
    mock_instance.analyze_scan_results = AsyncMock(return_value={
        'scan_id': 'test_scan_id_123',
        'findings_count': 2,
        'findings': [
            {'id': 'f1', 'severity': 'critical', 'risk_score': 85, 'finding_type': 'open_port', 'affected_asset': 'example.com', 'title': 'Critical Port'},
            {'id': 'f2', 'severity': 'info', 'risk_score': 10, 'finding_type': 'subdomain_discovered', 'affected_asset': 'example.com', 'title': 'Subdomain Discovered'}
        ],
        'statistics': {
            'total_findings': 2,
            'critical_findings': 1, 'high_findings': 0, 'medium_findings': 0, 'low_findings': 0, 'info_findings': 1,
            'open_findings': 2, 'resolved_findings': 0, 'false_positives': 0,
            'average_risk_score': 47.5
        }
    })
    mock_class = MagicMock(return_value=mock_instance)
    monkeypatch.setattr("src.cli.commands_analysis.AnalysisService", mock_class)
    return mock_instance

@pytest.fixture
def mock_click_echo(monkeypatch):
    """Mocks click.echo to capture output."""
    mock_echo = MagicMock()
    monkeypatch.setattr(click, 'echo', mock_echo)
    return mock_echo


@pytest.fixture
def mock_asyncio_run(monkeypatch):
    """Mocks asyncio.run to directly return the mocked result."""
    def mock_run_side_effect(coro):
        # For AsyncMock objects, we need to return the return_value attribute
        # Get the return value from the AsyncMock
        if hasattr(coro, '_mock_return_value'):
            return coro._mock_return_value
        # Fallback: just return the mocked value
        return {
            'scan_id': 'test_scan_id_123',
            'findings_count': 2,
            'findings': [
                {'id': 'f1', 'severity': 'critical', 'risk_score': 85, 'finding_type': 'open_port', 'affected_asset': 'example.com', 'title': 'Critical Port'},
                {'id': 'f2', 'severity': 'info', 'risk_score': 10, 'finding_type': 'subdomain_discovered', 'affected_asset': 'example.com', 'title': 'Subdomain Discovered'}
            ],
            'statistics': {
                'total_findings': 2,
                'critical_findings': 1, 'high_findings': 0, 'medium_findings': 0, 'low_findings': 0, 'info_findings': 1,
                'open_findings': 2, 'resolved_findings': 0, 'false_positives': 0,
                'average_risk_score': 47.5
            }
        }

    mock_run = MagicMock(side_effect=mock_run_side_effect)
    monkeypatch.setattr(asyncio, 'run', mock_run)
    return mock_run

# ============================================================================
# run_analysis_command tests
# ============================================================================
def test_run_analysis_command_scan_not_found(mock_db_manager, mock_click_echo):
    """Test run_analysis_command when scan ID is not found."""
    mock_db_manager.get_scan_status.return_value = None
    run_analysis_command('non_existent_scan_id')
    mock_click_echo.assert_called_with("❌ Scan non_existent_scan_id not found", err=True)

def test_run_analysis_command_scan_not_completed(mock_db_manager, mock_click_echo):
    """Test run_analysis_command when scan is not completed."""
    mock_db_manager.get_scan_status.return_value = {'scan_id': 'test_scan_id_123', 'status': 'running'}
    run_analysis_command('test_scan_id_123')
    mock_click_echo.assert_called_with("⚠️  Scan test_scan_id_123 is not completed (status: running)", err=True)

def test_run_analysis_command_analysis_disabled(mock_db_manager, mock_analysis_service, mock_click_echo):
    """Test run_analysis_command when AnalysisService is disabled."""
    mock_analysis_service.is_enabled.return_value = False
    run_analysis_command('test_scan_id_123')
    mock_click_echo.assert_called_with("❌ Analysis Layer is disabled in configuration", err=True)

def test_run_analysis_command_success_table_output(
    mock_db_manager, mock_analysis_service, mock_click_echo, mock_asyncio_run):
    """Test run_analysis_command success with table output."""
    run_analysis_command('test_scan_id_123')

    mock_db_manager.get_scan_status.assert_called_once_with('test_scan_id_123')
    mock_db_manager.get_tool_results.assert_any_call('test_scan_id_123', tool_name='subfinder')
    mock_db_manager.get_tool_results.assert_any_call('test_scan_id_123', tool_name='naabu')
    mock_analysis_service.is_enabled.assert_called_once()
    mock_asyncio_run.assert_called_once()
    mock_analysis_service.analyze_scan_results.assert_called_once()

    mock_click_echo.assert_any_call("🔍 Running analysis on scan test_scan_id_123...")
    mock_click_echo.assert_any_call("\n✅ Analysis completed!")
    mock_click_echo.assert_any_call("📊 Findings: 2")
    mock_click_echo.assert_any_call("  Critical: 1")
    mock_click_echo.assert_any_call("\n💡 Use 'openeasd findings --scan-id test_scan_id_123' to view details")

def test_run_analysis_command_success_json_output(
    mock_db_manager, mock_analysis_service, mock_click_echo, mock_asyncio_run):
    """Test run_analysis_command success with JSON output."""
    run_analysis_command('test_scan_id_123', output_format='json')

    mock_db_manager.get_scan_status.assert_called_once_with('test_scan_id_123')
    mock_analysis_service.is_enabled.assert_called_once()
    mock_asyncio_run.assert_called_once()
    mock_analysis_service.analyze_scan_results.assert_called_once()

    mock_click_echo.assert_called_with(json.dumps(mock_analysis_service.analyze_scan_results.return_value, indent=2))

def test_run_analysis_command_analysis_failure(
    mock_db_manager, mock_analysis_service, mock_click_echo):
    """Test run_analysis_command when analysis service fails."""
    mock_analysis_service.analyze_scan_results.side_effect = Exception("Analysis failed")

    with pytest.raises(Exception, match="Analysis failed"):
        run_analysis_command('test_scan_id_123')

    mock_click_echo.assert_called_with("❌ Analysis failed: Analysis failed", err=True)

# ============================================================================ 
# list_findings_command tests
# ============================================================================ 

def test_list_findings_command_no_findings(mock_db_manager, mock_click_echo):
    """Test list_findings_command when no findings are found."""
    mock_db_manager.get_findings.return_value = {'findings': [], 'total_count': 0}
    list_findings_command()
    mock_db_manager.get_findings.assert_called_once_with(scan_id=None, affected_asset=None, min_severity=None, limit=50)
    mock_click_echo.assert_called_with("ℹ️  No findings found")

def test_list_findings_command_success_table_output(mock_db_manager, mock_click_echo):
    """Test list_findings_command success with table output."""
    mock_db_manager.get_findings.return_value = {
        'findings': [
            {'id': 'f1', 'severity': 'critical', 'risk_score': 85, 'finding_type': 'open_port', 'affected_asset': 'example.com', 'title': 'Critical Port', 'status': 'open'},
            {'id': 'f2', 'severity': 'info', 'risk_score': 10, 'finding_type': 'subdomain_discovered', 'affected_asset': 'example.com', 'title': 'Subdomain Discovered', 'status': 'open'}
        ],
        'total_count': 2
    }
    list_findings_command(output_format='table')

    mock_db_manager.get_findings.assert_called_once()
    mock_click_echo.assert_any_call("\n🔍 Security Findings (2/2)")
    # Check that table was printed with the data
    calls_made = [str(call) for call in mock_click_echo.call_args_list]
    assert any('f1' in str(call) and 'critical' in str(call).lower() for call in calls_made), "Expected finding f1 with critical severity"

def test_list_findings_command_success_json_output(mock_db_manager, mock_click_echo):
    """Test list_findings_command success with JSON output."""
    mock_findings_data = {
        'findings': [
            {'id': 'f1', 'severity': 'critical', 'risk_score': 85, 'finding_type': 'open_port', 'affected_asset': 'example.com', 'title': 'Critical Port', 'status': 'open'}
        ],
        'total_count': 1
    }
    mock_db_manager.get_findings.return_value = mock_findings_data
    list_findings_command(output_format='json')

    mock_db_manager.get_findings.assert_called_once()
    mock_click_echo.assert_called_with(json.dumps(mock_findings_data, indent=2))

def test_list_findings_command_with_filters(mock_db_manager):
    """Test list_findings_command with various filters."""
    list_findings_command(scan_id='scan_abc', asset='host.com', min_severity='high', limit=10)
    mock_db_manager.get_findings.assert_called_once_with(scan_id='scan_abc', affected_asset='host.com', min_severity='high', limit=10)

def test_list_findings_command_has_more_findings(mock_db_manager, mock_click_echo):
    """Test list_findings_command displays hint for more findings."""
    mock_db_manager.get_findings.return_value = {
        'findings': [
            {'id': 'f1', 'severity': 'critical', 'risk_score': 85, 'finding_type': 'open_port', 'affected_asset': 'example.com', 'title': 'Critical Port', 'status': 'open'}
        ],
        'total_count': 5,
        'has_more': True
    }
    list_findings_command()
    mock_click_echo.assert_any_call("\n💡 4 more findings available. Use --limit to see more.")

def test_list_findings_command_retrieve_failure(mock_db_manager, mock_click_echo):
    """Test list_findings_command when findings retrieval fails."""
    mock_db_manager.get_findings.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        list_findings_command()
    mock_click_echo.assert_called_with("❌ Failed to retrieve findings: DB error", err=True)

# ============================================================================ 
# show_finding_command tests
# ============================================================================ 

def test_show_finding_command_not_found(mock_db_manager, mock_click_echo):
    """Test show_finding_command when finding is not found."""
    mock_db_manager.get_finding_by_id.return_value = None
    show_finding_command('non_existent_id')
    mock_click_echo.assert_called_with("❌ Finding non_existent_id not found", err=True)

def test_show_finding_command_success_table_output(mock_db_manager, mock_click_echo):
    """Test show_finding_command success with table output."""
    mock_db_manager.get_finding_by_id.return_value = {
        'id': 'f1',
        'scan_id': 's1',
        'finding_type': 'open_port',
        'affected_asset': 'example.com',
        'port': 80,
        'protocol': 'tcp',
        'service_name': 'HTTP',
        'severity': 'critical',
        'risk_score': 85,
        'confidence_level': 'high',
        'cwe_id': 'CWE-1',
        'title': 'Critical HTTP Port',
        'description': 'HTTP port 80 open',
        'remediation': 'Close port 80',
        'status': 'open',
        'false_positive': False,
        'discovered_at': datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        'updated_at': datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        'score_breakdown': {'base_score': 30, 'context_score': 40, 'exposure_score': 15, 'total': 85}
    }
    show_finding_command('f1')
    mock_db_manager.get_finding_by_id.assert_called_once_with('f1')
    mock_click_echo.assert_any_call("\n🔴 Security Finding Details")
    mock_click_echo.assert_any_call("  Severity:         🔴 CRITICAL") # Verify severity icon and text

def test_show_finding_command_success_json_output(mock_db_manager, mock_click_echo):
    """Test show_finding_command success with JSON output."""
    mock_finding_data = {
        'id': 'f1',
        'scan_id': 's1',
        'finding_type': 'open_port',
        'affected_asset': 'example.com',
        'severity': 'critical',
        'risk_score': 85,
        'title': 'Critical HTTP Port',
        'status': 'open'
    }
    mock_db_manager.get_finding_by_id.return_value = mock_finding_data
    show_finding_command('f1', output_format='json')
    mock_db_manager.get_finding_by_id.assert_called_once_with('f1')
    mock_click_echo.assert_called_with(json.dumps(mock_finding_data, indent=2))

def test_show_finding_command_retrieve_failure(mock_db_manager, mock_click_echo):
    """Test show_finding_command when finding retrieval fails."""
    mock_db_manager.get_finding_by_id.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        show_finding_command('f1')
    mock_click_echo.assert_called_with("❌ Failed to retrieve finding: DB error", err=True)

# ============================================================================ 
# findings_statistics_command tests
# ============================================================================ 

def test_findings_statistics_command_success_table_output(mock_db_manager, mock_click_echo):
    """Test findings_statistics_command success with table output."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total_findings': 10,
        'critical_findings': 2, 'high_findings': 3, 'medium_findings': 4, 'low_findings': 1, 'info_findings': 0,
        'open_findings': 8, 'resolved_findings': 1, 'false_positives': 1,
        'average_risk_score': 65.5
    }
    findings_statistics_command()
    mock_db_manager.get_findings_statistics.assert_called_once_with(scan_id=None, affected_asset=None)
    mock_click_echo.assert_any_call("\n📊 Findings Statistics")
    mock_click_echo.assert_any_call("  Total Findings:      10")
    mock_click_echo.assert_any_call("  🔴 Critical:         2")
    mock_click_echo.assert_any_call("  🟠 High:             3")

def test_findings_statistics_command_success_json_output(mock_db_manager, mock_click_echo):
    """Test findings_statistics_command success with JSON output."""
    mock_stats_data = {
        'total_findings': 5,
        'critical_findings': 1, 'high_findings': 1, 'medium_findings': 1, 'low_findings': 1, 'info_findings': 1,
        'open_findings': 5, 'resolved_findings': 0, 'false_positives': 0,
        'average_risk_score': 50
    }
    mock_db_manager.get_findings_statistics.return_value = mock_stats_data
    findings_statistics_command(output_format='json')
    mock_db_manager.get_findings_statistics.assert_called_once()
    mock_click_echo.assert_called_with(json.dumps(mock_stats_data, indent=2))

def test_findings_statistics_command_with_filters(mock_db_manager):
    """Test findings_statistics_command with filters."""
    findings_statistics_command(scan_id='scan_abc', asset='host.com')
    mock_db_manager.get_findings_statistics.assert_called_once_with(scan_id='scan_abc', affected_asset='host.com')

def test_findings_statistics_command_retrieve_failure(mock_db_manager, mock_click_echo):
    """Test findings_statistics_command when retrieval fails."""
    mock_db_manager.get_findings_statistics.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        findings_statistics_command()
    mock_click_echo.assert_called_with("❌ Failed to retrieve statistics: DB error", err=True)

# ============================================================================ 
# update_finding_status_command tests
# ============================================================================ 

def test_update_finding_status_command_invalid_status(mock_click_echo):
    """Test update_finding_status_command with an invalid status."""
    update_finding_status_command('f1', 'invalid_status')
    mock_click_echo.assert_called_with("❌ Invalid status. Must be one of: open, acknowledged, resolved, false_positive", err=True)

def test_update_finding_status_command_finding_not_found(mock_db_manager, mock_click_echo):
    """Test update_finding_status_command when finding is not found."""
    mock_db_manager.update_finding_status.return_value = False # Simulate finding not found
    update_finding_status_command('f1', 'resolved')
    mock_db_manager.update_finding_status.assert_called_once_with(finding_id='f1', status='resolved', resolution_notes=None)
    mock_click_echo.assert_called_with("❌ Finding f1 not found", err=True)

def test_update_finding_status_command_success_no_notes(mock_db_manager, mock_click_echo):
    """Test update_finding_status_command success without notes."""
    mock_db_manager.update_finding_status.return_value = True
    update_finding_status_command('f1', 'resolved')
    mock_db_manager.update_finding_status.assert_called_once_with(finding_id='f1', status='resolved', resolution_notes=None)
    mock_click_echo.assert_any_call("✅ Finding f1 status updated to 'resolved'")

def test_update_finding_status_command_success_with_notes(mock_db_manager, mock_click_echo):
    """Test update_finding_status_command success with notes."""
    mock_db_manager.update_finding_status.return_value = True
    update_finding_status_command('f1', 'resolved', notes='Fixed by team')
    mock_db_manager.update_finding_status.assert_called_once_with(finding_id='f1', status='resolved', resolution_notes='Fixed by team')
    mock_click_echo.assert_any_call("✅ Finding f1 status updated to 'resolved'")
    mock_click_echo.assert_any_call("📝 Resolution notes: Fixed by team")

def test_update_finding_status_command_update_failure(mock_db_manager, mock_click_echo):
    """Test update_finding_status_command when update fails."""
    mock_db_manager.update_finding_status.side_effect = Exception("DB error")
    with pytest.raises(Exception, match="DB error"):
        update_finding_status_command('f1', 'resolved')
    mock_click_echo.assert_called_with("❌ Failed to update finding status: DB error", err=True)
