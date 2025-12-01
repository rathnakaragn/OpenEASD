"""
Pytest configuration and shared fixtures for tests.

This module provides shared fixtures and configuration for all test modules.
"""

import pytest
import os
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient
from src.api.main import app
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.config import Config


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
        return TestClient(app)
