
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.cli.commands_results import (
    results_command,
    view_scans_command,
)

@pytest.fixture
def mock_db_manager():
    """Fixture for a mocked SQLModelManager."""
    db = MagicMock()
    db.get_scan_status.return_value = {
        'scan_id': 'scan_123',
        'status': 'completed',
        'start_time': datetime.now(),
        'end_time': datetime.now(),
        'domains_scanned': ['example.com'],
        'findings_count': 1
    }
    db.get_tool_results.return_value = {'results': []}
    db.get_scan_history.return_value = {'scans': []}
    return db

@patch('src.cli.commands_results.SQLModelManager')
def test_results_command(mock_sql_manager, mock_db_manager):
    """Test the 'results' command function."""
    mock_sql_manager.return_value = mock_db_manager
    
    args = {'scan_id': 'scan_123'}
    result = results_command(args)
    
    assert result['type'] == 'scan_results'
    assert result['scan']['scan_id'] == 'scan_123'
    mock_db_manager.get_scan_status.assert_called_with('scan_123')
    mock_db_manager.get_tool_results.assert_any_call('scan_123', 'subfinder', limit=10000)
    mock_db_manager.get_tool_results.assert_any_call('scan_123', 'naabu', limit=10000)

@patch('src.cli.commands_results.SQLModelManager')
def test_results_command_not_found(mock_sql_manager, mock_db_manager):
    """Test results command when scan ID is not found."""
    mock_db_manager.get_scan_status.return_value = None
    mock_sql_manager.return_value = mock_db_manager
    
    with pytest.raises(Exception):
        results_command({'scan_id': 'not-real'})

@patch('src.cli.commands_results.SQLModelManager')
def test_view_scans_command(mock_sql_manager, mock_db_manager):
    """Test the 'view_scans' command function."""
    mock_db_manager.get_scan_history.return_value = {
        'scans': [{
            'scan_id': 's1', 'domains_scanned': ['example.com'], 
            'start_time': datetime.now(), 'end_time': datetime.now()
        }]
    }
    mock_sql_manager.return_value = mock_db_manager
    
    args = {'limit': 10}
    result = view_scans_command(args)
    
    assert result['type'] == 'scan_list'
    assert len(result['scans']) == 1
    assert result['scans'][0]['scan_id'] == 's1'
    mock_db_manager.get_scan_history.assert_called_with(limit=10)
