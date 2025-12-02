
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

from src.cli.commands_scan import scan_command, batch_scan_subfinder_command

@pytest.fixture
def mock_db_manager():
    """Fixture for a mocked SQLModelManager."""
    db = MagicMock()
    db.create_scan_session.return_value = "scan_123"
    db.domain_exists.return_value = False
    db.get_domains.return_value = {'domains': [{'domain': 'example.com', 'is_primary': True}], 'total_count': 1}
    # Async mock for update_scan_status
    async def async_update_scan_status(*args, **kwargs):
        pass
    db.update_scan_status = AsyncMock(side_effect=async_update_scan_status)
    db.add_domain.return_value = MagicMock(domain="example.com")
    db.store_subfinder_results.return_value = None
    db.store_naabu_results.return_value = None
    return db

@pytest.fixture
def mock_alert_service():
    """Fixture for a mocked AlertManagementService."""
    service = MagicMock()
    service.create_alert_batch.return_value = []
    service.store_alerts.return_value = None
    return service

@patch('src.cli.commands_scan.SQLModelManager')
@patch('src.cli.commands_scan.run_subfinder', return_value=['sub.example.com'])
@patch('src.cli.commands_scan.run_dnsx', return_value=[{'host': 'sub.example.com', 'a': ['1.1.1.1']}])
@patch('src.cli.commands_scan.run_naabu', return_value=[{'subdomain': 'sub.example.com', 'port': 80, 'protocol': 'tcp', 'ip': '1.1.1.1'}])
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
@patch('src.cli.commands_scan.get_ist_now', return_value=datetime.now())
def test_scan_command_full_workflow(
    mock_get_ist_now,
    mock_validate_domain,
    mock_run_naabu,
    mock_run_dnsx,
    mock_run_subfinder,
    mock_sql_manager,
    mock_db_manager,
    capsys
):
    """Test the full scan workflow of scan_command."""
    mock_sql_manager.return_value = mock_db_manager

    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    result = scan_command(args)
    
    assert result['scan_id'] == 'scan_123'
    assert 'sub.example.com' in result['subdomains']
    assert mock_run_subfinder.called
    assert mock_run_dnsx.called
    assert mock_run_naabu.called
    assert mock_db_manager.create_scan_session.called

@patch('src.cli.commands_scan.SQLModelManager')
@patch('src.cli.commands_scan.run_subfinder', return_value=[])
@patch('src.cli.commands_scan.run_dnsx', return_value=[])
@patch('src.cli.commands_scan.run_naabu', return_value=[])
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
@patch('src.cli.commands_scan.get_ist_now', return_value=datetime.now())
def test_scan_command_no_subdomains(
    mock_get_ist_now,
    mock_validate_domain,
    mock_run_naabu,
    mock_run_dnsx,
    mock_run_subfinder,
    mock_sql_manager,
    mock_db_manager,
    capsys
):
    """Test scan_command when no subdomains are found."""
    mock_sql_manager.return_value = mock_db_manager

    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    result = scan_command(args)
    
    assert result['scan_id'] == 'scan_123'
    assert len(result['subdomains']) == 0
    assert not mock_run_dnsx.called
    assert not mock_run_naabu.called
    assert mock_db_manager.update_scan_status.called

@patch('src.cli.commands_scan.SQLModelManager')
@patch('src.cli.commands_scan.run_subfinder', side_effect=Exception("Subfinder failed"))
@patch('src.cli.commands_scan.validate_domain', side_effect=lambda x: x)
@patch('src.cli.commands_scan.get_ist_now', return_value=datetime.now())
def test_scan_command_failure(
    mock_get_ist_now,
    mock_validate_domain,
    mock_run_subfinder,
    mock_sql_manager,
    mock_db_manager,
    capsys
):
    """Test scan_command error handling."""
    mock_sql_manager.return_value = mock_db_manager
    
    args = {'domain': 'example.com', 'timeout': 300, 'save': True}
    with pytest.raises(Exception, match="Subfinder failed"):
        scan_command(args)
    
    mock_db_manager.update_scan_status.assert_called_with('scan_123', 'failed', end_time=mock_get_ist_now.return_value)

@patch('src.cli.commands_scan.SQLModelManager')
@patch('src.cli.commands_scan.run_subfinder', return_value=['sub.example.com'])
@patch('src.cli.commands_scan.run_dnsx', return_value=[{'host': 'sub.example.com', 'a': ['1.1.1.1']}])
@patch('src.cli.commands_scan.run_naabu', return_value=[])
@patch('src.cli.commands_scan.get_ist_now', return_value=datetime.now())
def test_batch_scan_subfinder_command_success(
    mock_get_ist_now,
    mock_run_naabu,
    mock_run_dnsx,
    mock_run_subfinder,
    mock_sql_manager,
    mock_db_manager,
    capsys
):
    """Test batch_scan_subfinder_command success path."""
    mock_sql_manager.return_value = mock_db_manager
    mock_db_manager.get_domains.return_value = {
        'domains': [{'domain': 'example.com', 'is_primary': True}], 'total_count': 1
    }
    
    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)
    
    assert result['success']
    assert result['total_domains'] == 1
    assert result['successful_scans'] == 1
    assert result['failed_scans'] == 0
    assert mock_db_manager.create_scan_session.called
    assert mock_run_subfinder.called
    assert mock_db_manager.store_subfinder_results.called
    assert mock_db_manager.update_scan_status.called

@patch('src.cli.commands_scan.SQLModelManager')
def test_batch_scan_subfinder_command_no_domains(mock_sql_manager, mock_db_manager):
    """Test batch_scan_subfinder_command with no domains in DB."""
    mock_sql_manager.return_value = mock_db_manager
    mock_db_manager.get_domains.return_value = {'domains': [], 'total_count': 0}
    
    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)
    
    assert result['success']
    assert "No domains found" in result['message']
    assert result['total_domains'] == 0

@patch('src.cli.commands_scan.SQLModelManager')
@patch('src.cli.commands_scan.run_subfinder', side_effect=Exception("Subfinder failed"))
@patch('src.cli.commands_scan.get_ist_now', return_value=datetime.now())
def test_batch_scan_subfinder_command_scan_failure(
    mock_get_ist_now,
    mock_run_subfinder,
    mock_sql_manager,
    mock_db_manager,
    capsys
):
    """Test batch_scan_subfinder_command when an individual scan fails."""
    mock_sql_manager.return_value = mock_db_manager
    mock_db_manager.get_domains.return_value = {
        'domains': [{'domain': 'example.com', 'is_primary': True}], 'total_count': 1
    }
    mock_db_manager.create_scan_session.return_value = 'scan_123'
    
    args = {'timeout': 300, 'primary': False}
    result = batch_scan_subfinder_command(args)
    
    assert result['success']
    assert result['total_domains'] == 1
    assert result['successful_scans'] == 0
    assert result['failed_scans'] == 1
    mock_db_manager.update_scan_status.assert_called_with('scan_123', 'failed', end_time=mock_get_ist_now.return_value)
    assert "Scan failed" in capsys.readouterr().out
