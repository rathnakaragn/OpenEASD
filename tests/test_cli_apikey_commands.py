"""
Comprehensive test suite for CLI API key management commands.

Tests apikey create, list, and revoke commands.
"""

import pytest
from unittest.mock import MagicMock, patch
from src.cli.commands_apikey import (
    apikey_create_command,
    apikey_list_command,
    apikey_revoke_command
)


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    return MagicMock()


class TestApikeyCreateCommand:
    """Test apikey create command."""

    def test_create_api_key_success(self, mock_db_manager):
        """Test successful API key creation."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = {
                'key_id': 'key-123',
                'plain_key': 'secret-abc123',
                'permissions': ['*'],
                'created_at': '2025-11-28T10:00:00Z'
            }

            args = {
                'name': 'test-api-key',
                'permissions': ['*']
            }

            result = apikey_create_command(args)
            assert result['success'] is True
            assert 'key_id' in result
            assert 'plain_key' in result

    def test_create_api_key_with_specific_permissions(self, mock_db_manager):
        """Test creating API key with specific permissions."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = {
                'key_id': 'key-456',
                'plain_key': 'secret-xyz789',
                'permissions': ['domain:write'],
                'created_at': '2025-11-28T10:00:00Z'
            }

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

            result = apikey_create_command(args)
            assert result['success'] is False

    def test_create_api_key_initialization(self, mock_db_manager):
        """Test that database is properly initialized."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.create_api_key.return_value = {
                'key_id': 'key-789',
                'plain_key': 'secret-def456',
                'permissions': ['*'],
                'created_at': '2025-11-28T10:00:00Z'
            }

            args = {
                'name': 'new-key',
                'permissions': ['*']
            }

            result = apikey_create_command(args)
            mock_db_manager.initialize.assert_called()


class TestApikeyListCommand:
    """Test apikey list command."""

    def test_list_api_keys_success(self, mock_db_manager):
        """Test successful listing of API keys."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = {
                'api_keys': [
                    {
                        'key_id': 'key-1',
                        'name': 'prod-key',
                        'permissions': ['*'],
                        'created_at': '2025-11-28T10:00:00Z',
                        'last_used_at': '2025-11-28T11:00:00Z'
                    },
                    {
                        'key_id': 'key-2',
                        'name': 'dev-key',
                        'permissions': ['domain:write'],
                        'created_at': '2025-11-27T10:00:00Z',
                        'last_used_at': None
                    }
                ],
                'total': 2
            }

            args = {}

            result = apikey_list_command(args)
            assert result['success'] is True
            assert len(result['api_keys']) == 2

    def test_list_api_keys_empty(self, mock_db_manager):
        """Test listing when no API keys exist."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = {
                'api_keys': [],
                'total': 0
            }

            args = {}

            result = apikey_list_command(args)
            assert result['success'] is True
            assert len(result['api_keys']) == 0

    def test_list_api_keys_database_error(self, mock_db_manager):
        """Test error handling for database failures."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.side_effect = Exception("DB error")

            args = {}

            result = apikey_list_command(args)
            assert result['success'] is False

    def test_list_api_keys_includes_metadata(self, mock_db_manager):
        """Test that API key metadata is returned."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.list_api_keys.return_value = {
                'api_keys': [
                    {
                        'key_id': 'key-1',
                        'name': 'test-key',
                        'permissions': ['*'],
                        'created_at': '2025-11-28T10:00:00Z',
                        'last_used_at': '2025-11-28T11:00:00Z'
                    }
                ],
                'total': 1
            }

            args = {}

            result = apikey_list_command(args)
            assert result['api_keys'][0]['name'] == 'test-key'
            assert 'created_at' in result['api_keys'][0]
            assert 'last_used_at' in result['api_keys'][0]


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

            result = apikey_revoke_command(args)
            assert result['success'] is False

    def test_revoke_api_key_database_error(self, mock_db_manager):
        """Test error handling for database failures."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.side_effect = Exception("DB error")

            args = {
                'key_id': 'key-123'
            }

            result = apikey_revoke_command(args)
            assert result['success'] is False

    def test_revoke_already_revoked_key(self, mock_db_manager):
        """Test revoking an already revoked key."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = False

            args = {
                'key_id': 'already-revoked-key'
            }

            result = apikey_revoke_command(args)
            assert result['success'] is False

    def test_revoke_api_key_initialization(self, mock_db_manager):
        """Test that database is properly initialized during revoke."""
        with patch('src.cli.commands_apikey.SQLModelManager', return_value=mock_db_manager):
            mock_db_manager.revoke_api_key.return_value = True

            args = {
                'key_id': 'key-123'
            }

            result = apikey_revoke_command(args)
            mock_db_manager.initialize.assert_called()
