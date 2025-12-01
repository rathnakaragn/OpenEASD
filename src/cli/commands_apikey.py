"""
API key management commands for OpenEASD CLI.

Handles creating, listing, and revoking API keys for write operation authentication.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

import secrets
import hashlib
from typing import Dict, Any
from src.data.database.sqlmodel_manager import SQLModelManager


def generate_api_key() -> tuple:
    """
    Generate a secure API key.

    Returns:
        Tuple of (plain_key, hashed_key)
    """
    # Generate random 32-byte key
    plain_key = secrets.token_urlsafe(32)

    # Hash for storage
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    return plain_key, hashed_key


def apikey_create_command(args) -> Dict[str, Any]:
    """
    Create a new API key.

    Args:
        args: Parsed command arguments containing:
            - name: Human-readable name for the key
            - permissions: List of permissions

    Returns:
        API key creation result
    """
    name = args.get('name')
    permissions = args.get('permissions', ['*'])  # Default to all permissions

    # Generate API key
    plain_key, hashed_key = generate_api_key()

    # Store in database
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        result = db_manager.create_api_key(
            key_hash=hashed_key,
            name=name,
            permissions=permissions
        )

        return {
            'success': True,
            'type': 'apikey_create',
            'api_key': plain_key,  # Show once to user
            'key_id': result['id'],
            'name': result['name'],
            'permissions': result['permissions'],
            'created_at': result['created_at']
        }

    finally:
        db_manager.close()

def apikey_list_command(args) -> Dict[str, Any]:
    """
    List all API keys.

    Args:
        args: Parsed command arguments

    Returns:
        List of API keys (without the actual key values)
    """
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        api_keys = db_manager.list_api_keys()

        return {
            'success': True,
            'type': 'apikey_list',
            'api_keys': api_keys,  # Already formatted as dicts by SQLModelManager
            'total': len(api_keys),
        }

    finally:
        db_manager.close()


def apikey_revoke_command(args) -> Dict[str, Any]:
    """
    Revoke an API key.

    Args:
        args: Parsed command arguments containing:
            - key_id: ID of the key to revoke

    Returns:
        Revocation result
    """
    key_id = args.get('key_id')

    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        success = db_manager.revoke_api_key(key_id)

        if not success:
            raise ValueError(f"API key not found: {key_id}")

        return {
            'success': True,
            'type': 'apikey_revoke',
            'message': f"API key {key_id} has been revoked",
            'key_id': key_id
        }

    finally:
        db_manager.close()
