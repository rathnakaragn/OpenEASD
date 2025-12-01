"""
Comprehensive test suite for CLI API key management commands.
"""

import pytest
from unittest.mock import MagicMock, patch
from src.cli.commands_apikey import (
    apikey_create_command,
    apikey_list_command,
    apikey_revoke_command
)
from src.data.models.api_key import APIKey

@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    return MagicMock()

class TestApikeyCreateCommand:
    """Test apikey create command."""

    def test_create_api_key_success(self, mock_db_manager):
        """Test successful API key creation."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = APIKey(
                id='key-123',
                name='test-api-key',
                permissions='["*"]',
                key='some_key'
            )

            args = {
                'name': 'test-api-key',
                'permissions': ['*']
            }

            result = apikey_create_command(args)
            assert result['success'] is True
            assert 'key_id' in result
            assert 'api_key' in result

    def test_create_api_key_with_specific_permissions(self, mock_db_manager):
        """Test creating API key with specific permissions."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = APIKey(
                id='key-456',
                name='domain-writer',
                permissions='["domain:write"]',
                key='some_key'
            )

            args = {
                'name': 'domain-writer',
                'permissions': ['domain:write']
            }

            result = apikey_create_command(args)
            assert result['success'] is True
            mock_db_manager.create_api_key.assert_called_once()

    def test_create_api_key_database_error(self, mock_db_manager):
        """Test error handling for database failures."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.side_effect = Exception("Database error")

            args = {
                'name': 'test-key',
                'permissions': ['*']
            }

            with pytest.raises(Exception, match="Database error"):
                apikey_create_command(args)

    def test_create_api_key_initialization(self, mock_db_manager):
        """Test that database is properly initialized."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = APIKey(
                id='key-789',
                name='new-key',
                permissions='["*"]',
                key='some_key'
            )

            args = {
                'name': 'new-key',
                'permissions': ['*']
            }

            apikey_create_command(args)
            mock_db_manager.initialize.assert_called()


class TestApikeyListCommand:
    """Test apikey list command."""

    def test_list_api_keys_success(self, mock_db_manager):
        """Test successful listing of API keys."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = [
                APIKey(id='key-1', name='prod-key', permissions='["*"]', key='key1'),
                APIKey(id='key-2', name='dev-key', permissions='["domain:write"]', key='key2')
            ]

            args = {}

            result = apikey_list_command(args)
            assert result['success'] is True
            assert len(result['api_keys']) == 2

    def test_list_api_keys_empty(self, mock_db_manager):
        """Test listing when no API keys exist."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = []

            args = {}

            result = apikey_list_command(args)
            assert result['success'] is True
            assert len(result['api_keys']) == 0

    def test_list_api_keys_database_error(self, mock_db_manager):
        """Test error handling for database failures."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.side_effect = Exception("DB error")

            args = {}

            with pytest.raises(Exception, match="DB error"):
                apikey_list_command(args)

    def test_list_api_keys_includes_metadata(self, mock_db_manager):
        """Test that API key metadata is returned."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = [
                APIKey(id='key-1', name='test-key', permissions='["*"]', key='key1')
            ]

            args = {}

            result = apikey_list_command(args)
            assert result['api_keys'][0]['name'] == 'test-key'


class TestApikeyRevokeCommand:
    """Test apikey revoke command."""

    def test_revoke_api_key_success(self, mock_db_manager):
        """Test successful API key revocation."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = True

            args = {
                'key_id': 'key-123'
            }

            result = apikey_revoke_command(args)
            assert result['success'] is True

    def test_revoke_api_key_not_found(self, mock_db_manager):
        """Test revoking non-existent API key."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = False

            args = {
                'key_id': 'nonexistent-key'
            }

            with pytest.raises(ValueError, match="API key not found"):
                apikey_revoke_command(args)

    def test_revoke_api_key_database_error(self, mock_db_manager):
        """Test error handling for database failures."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.side_effect = Exception("DB error")

            args = {
                'key_id': 'key-123'
            }

            with pytest.raises(Exception, match="DB error"):
                apikey_revoke_command(args)

    def test_revoke_already_revoked_key(self, mock_db_manager):
        """Test revoking an already revoked key."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = False

            args = {
                'key_id': 'already-revoked-key'
            }

            with pytest.raises(ValueError, match="API key not found"):
                apikey_revoke_command(args)

    def test_revoke_api_key_initialization(self, mock_db_manager):
        """Test that database is properly initialized during revoke."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = True

            args = {
                'key_id': 'key-123'
            }

            apikey_revoke_command(args)
            mock_db_manager.initialize.assert_called()
