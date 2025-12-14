import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import sys
import importlib
import runpy

from src.api.main import app, lifespan

@pytest.fixture(autouse=True)
def cleanup_imports():
    """Clean up any modified modules after each test."""
    yield
    if 'src.api.main' in sys.modules:
        importlib.reload(sys.modules['src.api.main'])

def test_read_index():
    """Test that the root path serves the index.html file."""
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    # Check for OpenEASD dashboard content
    assert "OpenEASD" in response.text
    assert "Attack Surface Detection" in response.text

def test_catch_all_serves_index():
    """Test that an unknown path serves the index.html file."""
    client = TestClient(app)

    response = client.get("/some/unknown/path")
    assert response.status_code == 200
    # Check for OpenEASD dashboard content
    assert "OpenEASD" in response.text

def test_catch_all_api_404():
    """Test that the catch-all route correctly returns 404 for api paths."""
    client = TestClient(app)
    response = client.get("/api/v1/nonexistent")
    assert response.status_code == 404

@patch('os.path.exists', return_value=False)
def test_no_frontend_dir(mock_exists):
    """Test that the app doesn't crash if the frontend dir doesn't exist."""
    importlib.reload(sys.modules['src.api.main'])
    client = TestClient(sys.modules['src.api.main'].app)
    response = client.get("/")
    assert response.status_code == 404

@patch('src.api.main.setup_logging')
@patch('src.api.main.logger')
def test_lifespan(mock_logger, mock_setup_logging):
    """Test the lifespan startup and shutdown events."""
    from fastapi import FastAPI

    # Create a new app instance just for this test
    test_app = FastAPI(lifespan=lifespan)

    with TestClient(test_app) as client:
        mock_setup_logging.assert_called_once()
        mock_logger.info.assert_any_call("🚀 OpenEASD API starting up...")

    mock_logger.info.assert_any_call("👋 OpenEASD API shutting down...")


@patch('uvicorn.run')
def test_main_entrypoint(mock_uvicorn_run):
    """Test the main function for running with uvicorn."""
    runpy.run_module("src.api.main", run_name="__main__")
    mock_uvicorn_run.assert_called_once()