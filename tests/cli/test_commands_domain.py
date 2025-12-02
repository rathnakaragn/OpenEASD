
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
def mock_db_manager():
    """Fixture for a mocked SQLModelManager."""
    return MagicMock()

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_add_command(mock_sql_manager, mock_db_manager):
    """Test the 'domain_add' command function."""
    mock_sql_manager.return_value = mock_db_manager
    
    with patch('src.cli.commands_domain.DomainService') as mock_service:
        mock_service_instance = mock_service.return_value
        mock_service_instance.create_domain.return_value = MagicMock(domain="example.com")
        
        result = domain_add_command("example.com", True, None, None)
        assert result['success']
        assert "example.com" in result['message']

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_add_command_exists(mock_sql_manager, mock_db_manager):
    """Test adding a domain that already exists."""
    mock_sql_manager.return_value = mock_db_manager
    with patch('src.cli.commands_domain.DomainService') as mock_service:
        mock_service.return_value.create_domain.side_effect = DomainAlreadyExists
        with pytest.raises(Exception):
            domain_add_command("example.com", False, None, None)

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_list_command(mock_sql_manager, mock_db_manager):
    """Test the 'domain_list' command function."""
    mock_sql_manager.return_value = mock_db_manager
    with patch('src.cli.commands_domain.DomainService') as mock_service:
        mock_domain = MagicMock()
        mock_domain.model_dump.return_value = {'domain': 'example.com'}
        mock_service.return_value.list_domains.return_value = {'domains': [mock_domain], 'total_count': 1, 'has_more': False}
        
        result = domain_list_command(10, False, False, 'table')
        assert result['success']
        assert len(result['domains']) == 1

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_update_command(mock_sql_manager, mock_db_manager):
    """Test the 'domain_update' command function."""
    mock_sql_manager.return_value = mock_db_manager
    with patch('src.cli.commands_domain.DomainService') as mock_service:
        mock_service.return_value.update_domain.return_value = MagicMock(domain="example.com")
        
        result = domain_update_command("example.com", True)
        assert result['success']

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_remove_command(mock_sql_manager, mock_db_manager):
    """Test the 'domain_remove' command function."""
    mock_sql_manager.return_value = mock_db_manager
    with patch('src.cli.commands_domain.DomainService') as mock_service, \
         patch('click.confirm', return_value=True):
        mock_service.return_value.delete_domain.return_value = {'success': True}
        
        result = domain_remove_command("example.com", False)
        assert result['success']

@patch('src.cli.commands_domain.SQLModelManager')
def test_domain_remove_command_force(mock_sql_manager, mock_db_manager):
    """Test force removing a domain."""
    mock_sql_manager.return_value = mock_db_manager
    with patch('src.cli.commands_domain.DomainService') as mock_service, \
         patch('click.confirm') as mock_confirm:
        mock_service.return_value.delete_domain.return_value = {'success': True}

        result = domain_remove_command("example.com", True) # force=True
        assert result['success']
        mock_confirm.assert_not_called()
