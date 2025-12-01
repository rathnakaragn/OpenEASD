"""
Pytest configuration and shared fixtures for tests.

This module provides shared fixtures and configuration for all test modules.
"""

import pytest
import hashlib
import secrets
import os
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient
from src.api.main import app
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.config import Config # Import Config to mock it
from fastapi import FastAPI # Import FastAPI to patch its add_middleware

import asyncio
from src.api.main import app, lifespan # Import lifespan

# Mock FastAPI.add_middleware to prevent RateLimitMiddleware from being added
original_add_middleware = FastAPI.add_middleware
def mock_add_middleware(app_instance, middleware_class, **kwargs):
    # Dynamically import RateLimitMiddleware here to avoid global import issues
    from src.api.middleware import RateLimitMiddleware 
    if middleware_class == RateLimitMiddleware:
        # Skip adding RateLimitMiddleware for tests
        pass
    else:
        original_add_middleware(app_instance, middleware_class, **kwargs)

@pytest.fixture(scope="function")
def mock_config():
    """Mock Config object for testing."""
    m_config = MagicMock(spec=Config)
    m_config.get.side_effect = lambda key, default: {
        'api.title': 'Test API',
        'api.description': 'Test Description',
        'api.version': '1.0.0',
        'api.host': '0.0.0.0',
        'api.port': 8000,
        'api.docs_url': '/docs',
        'api.redoc_url': '/redoc',
        'api.openapi_url': '/openapi.json',
        'api.cors.allow_origins': ['*'],
        'api.cors.allow_credentials': True,
        'api.cors.allow_methods': ['*'],
        'api.cors.allow_headers': ['*'],
        'api.frontend_dir': 'non_existent_frontend_dir',
        'api.reload': False,
        'log_level': 'INFO',
    }.get(key, default)
    return m_config

@pytest.fixture(scope="function")
def db_manager():
    """Database manager for test setup with cleanup."""
    db = SQLModelManager()
    db.initialize()
    yield db
    # Cleanup: Close database between tests
    db.close()


@pytest.fixture(scope="function")
def client(mock_config):
    """FastAPI test client."""
    with patch('src.utils.config.Config', return_value=mock_config):
        with patch.object(FastAPI, 'add_middleware', new=mock_add_middleware):
            # Patch EventBusManager as it's imported in src.api.routes.events
            with patch('src.api.routes.events.EventBusManager.is_running', return_value=True), \
                 patch('src.api.routes.events.EventBusManager.get_ipc_path', return_value="/tmp/test_openeasd_events.ipc"):
                return TestClient(app)


@pytest.fixture(scope="function")
def admin_key(db_manager):
    """Create an admin API key with all permissions."""
    # Use unique keys to avoid UNIQUE constraint failures
    plain_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    db_manager.create_api_key(
        key_hash=hashed_key,
        name="admin",
        permissions=["*"]
    )

    return plain_key


@pytest.fixture(scope="function")
def domain_writer_key(db_manager):
    """Create an API key for domain writing only."""
    plain_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    db_manager.create_api_key(
        key_hash=hashed_key,
        name="domain_writer",
        permissions=["domain:write"]
    )

    return plain_key


@pytest.fixture(scope="function")
def scan_executor_key(db_manager):
    """Create an API key for scan execution only."""
    plain_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    db_manager.create_api_key(
        key_hash=hashed_key,
        name="scan_executor",
        permissions=["scan:execute"]
    )

    return plain_key


@pytest.fixture(scope="function")
def test_api_key(db_manager):
    """Create a test API key with all permissions."""
    plain_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    result = db_manager.create_api_key(
        key_hash=hashed_key,
        name="test_key",
        permissions=["*"]  # All permissions
    )

    return plain_key


@pytest.fixture(scope="function")
def test_api_key_limited(db_manager):
    """Create a test API key with limited permissions."""
    plain_key = secrets.token_urlsafe(32)
    hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

    result = db_manager.create_api_key(
        key_hash=hashed_key,
        name="limited_key",
        permissions=["domain:write"]  # Only domain write
    )

    return plain_key