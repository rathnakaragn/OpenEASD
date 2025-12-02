
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

from src.api.main import app  # Assuming your FastAPI app instance is in src.api.main
from src.api.dependencies import get_db_manager

# Create a TestClient
client = TestClient(app)

def test_health_check_success():
    """Test the health check endpoint with a successful DB connection."""
    
    # Mock the get_db_manager dependency
    mock_db_manager = MagicMock()
    # Mock the context manager for the session
    mock_session = MagicMock()
    mock_db_manager.engine.connect.return_value.__enter__.return_value = mock_session

    def override_get_db():
        yield mock_db_manager

    app.dependency_overrides[get_db_manager] = override_get_db

    response = client.get("/api/v1/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert "version" in data

    # Clean up the override
    app.dependency_overrides = {}


def test_health_check_db_error():
    """Test the health check endpoint with a database connection error."""

    mock_db_manager = MagicMock()
    # Make the session raise an exception
    mock_db_manager.engine.connect.side_effect = Exception("DB connection failed")

    def override_get_db():
        yield mock_db_manager

    app.dependency_overrides[get_db_manager] = override_get_db
    
    response = client.get("/api/v1/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "error: DB connection failed" in data["database"]

    # Clean up
    app.dependency_overrides = {}
