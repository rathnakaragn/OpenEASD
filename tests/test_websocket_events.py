"""
Tests for WebSocket event streaming endpoint.
"""

import pytest
from starlette.testclient import TestClient
from src.api.main import app
from src.messaging.manager import EventBusManager
import json
import time


@pytest.fixture(scope="module", autouse=True)
def setup_event_bus():
    """Start EventBus for WebSocket tests."""
    # EventBus should be started by the API lifespan, but ensure it's running
    if not EventBusManager.is_running():
        EventBusManager.start()
    yield
    # Keep it running for other tests


def test_events_status_endpoint():
    """Test that the events status endpoint works."""
    client = TestClient(app)
    response = client.get("/api/v1/events/status")

    assert response.status_code == 200
    data = response.json()

    assert "event_bus_running" in data
    assert "ipc_path" in data
    assert "websocket_endpoint" in data
    assert "supported_topics" in data
    assert "example_url" in data

    # EventBus should be running
    assert data["event_bus_running"] is True


def test_websocket_connection():
    """Test basic WebSocket connection."""
    client = TestClient(app)

    with client.websocket_connect("/api/v1/events?topics=scan.*") as websocket:
        # Should receive connection confirmation
        data = websocket.receive_json()

        assert data["type"] == "connected"
        assert "topics" in data
        assert "scan.*" in data["topics"]
        assert "message" in data


@pytest.mark.skip(reason="TestClient doesn't fully support async WebSocket patterns")
def test_websocket_ping_pong():
    """Test ping/pong with WebSocket."""
    client = TestClient(app)

    with client.websocket_connect("/api/v1/events") as websocket:
        # Receive connection message
        websocket.receive_json()

        # Send ping
        websocket.send_json({"type": "ping"})

        # Should receive pong within reasonable time
        for _ in range(10):  # Try up to 10 times (1 second)
            try:
                data = websocket.receive_json(timeout=0.1)
                if data.get("type") == "pong":
                    break
            except:
                time.sleep(0.1)
        else:
            pytest.fail("Did not receive pong response")


@pytest.mark.skip(reason="TestClient WebSocket doesn't work well with async event loops")
def test_websocket_receives_events():
    """Test that WebSocket receives events when they are published."""
    # This test would work in a real environment but TestClient has limitations
    # For manual testing: use wscat or a WebSocket client
    pass


@pytest.mark.skip(reason="TestClient WebSocket doesn't work well with async event loops")
def test_websocket_topic_filtering():
    """Test that WebSocket only receives events for subscribed topics."""
    # This test would work in a real environment but TestClient has limitations
    # For manual testing: use wscat or a WebSocket client
    pass
