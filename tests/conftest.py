"""
Pytest configuration and shared fixtures for tests.

This module provides shared fixtures and configuration for all test modules.
"""

import pytest
import hashlib
import secrets
from starlette.testclient import TestClient
from src.api.main import app
from src.data.database.sqlmodel_manager import SQLModelManager


@pytest.fixture(scope="function", autouse=True)
def reset_rate_limits():
    """Reset rate limit middleware state before each test."""
    from src.api.middleware.rate_limit import RateLimitMiddleware
    RateLimitMiddleware.reset()
    yield


@pytest.fixture(scope="function")
def db_manager():
    """Database manager for test setup with cleanup."""
    db = SQLModelManager()
    db.initialize()
    yield db
    # Cleanup: Close database between tests
    db.close()


@pytest.fixture(scope="function")
def client():
    """FastAPI test client."""
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
