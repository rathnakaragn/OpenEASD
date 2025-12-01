"""
Tests for WebSocket event streaming endpoint.
"""
import pytest
from starlette.testclient import TestClient
from src.api.main import app
from src.messaging.manager import EventBusManager
import json
import time
from unittest.mock import patch, MagicMock
from fastapi import WebSocketDisconnect


def test_events_status_endpoint():
    """Test that the events status endpoint works."""
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=True), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)
        response = client.get("/api/v1/events/status")

        assert response.status_code == 200
        data = response.json()

        assert "event_bus_running" in data
        assert "ipc_path" in data
        assert "websocket_endpoint" in data
        assert "supported_topics" in data
        assert "example_url" in data

        assert data["event_bus_running"] is True


def test_websocket_connection(admin_key):
    """Test basic WebSocket connection."""
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=True), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)

        with client.websocket_connect(f"/api/v1/events?topics=scan.*&api_key={admin_key}") as websocket:
            data = websocket.receive_json()

            assert data["type"] == "connected"
            assert "topics" in data
            assert "scan.*" in data["topics"]
            assert "message" in data


def test_websocket_connection_no_api_key():
    """Test WebSocket connection without an API key (authentication failure)."""
    # EventBusManager state doesn't matter much for early auth failure
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=True), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)

        with client.websocket_connect("/api/v1/events?topics=scan.*") as websocket:
            data = websocket.receive_json()

            assert data["type"] == "error"
            assert "Authentication failed" in data["error"]


def test_websocket_connection_eventbus_not_running(admin_key):
    """Test WebSocket connection when EventBusManager is not running."""
    # Only patch is_running to False, get_ipc_path still returns a value
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=False), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)

        with client.websocket_connect(f"/api/v1/events?topics=scan.*&api_key={admin_key}") as websocket:
            data = websocket.receive_json()

            assert data["type"] == "error"
            assert "EventBus is not running" in data["error"]


def test_websocket_connection_with_different_topics(admin_key):
    """Test WebSocket connection with custom topics."""
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=True), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)
        custom_topics = "tool.*,finding.critical"

        with client.websocket_connect(f"/api/v1/events?topics={custom_topics}&api_key={admin_key}") as websocket:
            data = websocket.receive_json()

            assert data["type"] == "connected"
            assert "topics" in data
            assert "tool.*" in data["topics"]
            assert "finding.critical" in data["topics"]
            assert "message" in data


def test_websocket_connection_receives_ping_pong(admin_key):
    """Test ping/pong with WebSocket with a valid API key."""
    with patch('src.messaging.manager.EventBusManager.is_running', return_value=True), \
         patch('src.messaging.manager.EventBusManager.get_ipc_path', return_value='/tmp/test_openeasd_events.ipc'):
        client = TestClient(app)

        with patch('src.messaging.subscriber.EventSubscriber') as MockEventSubscriber:
            mock_subscriber_instance = MockEventSubscriber.return_value
            mock_subscriber_instance.poll.side_effect = [None, {'type': 'ping', 'message': 'test ping'}]

            with client.websocket_connect(f"/api/v1/events?api_key={admin_key}") as websocket:
                websocket.receive_json() # Connection confirmation

                websocket.send_json({"type": "ping"})

                received_pong_response = False
                for _ in range(5):
                    try:
                        data = websocket.receive_json()
                        if data.get("type") == "pong":
                            received_pong_response = True
                            break
                    except WebSocketDisconnect:
                        break
                    except Exception:
                        pass

                assert received_pong_response, "Did not receive pong response after sending ping"

                received_event = False
                for _ in range(5):
                    try:
                        data = websocket.receive_json()
                        if data.get('type') == 'ping' and data.get('message') == 'test ping':
                            received_event = True
                            break
                    except WebSocketDisconnect:
                        break
                    except Exception:
                            pass

                assert received_event, "Did not receive mocked event from server"


# The following tests are still skipped as they are complex to implement reliably with TestClient
@pytest.mark.skip(reason="TestClient WebSocket doesn't work well with async event loops for complex event scenarios")
def test_websocket_receives_events():
    """Test that WebSocket receives events when they are published."""
    pass


@pytest.mark.skip(reason="TestClient WebSocket doesn't work well with async event loops for complex event scenarios")
def test_websocket_topic_filtering():
    """Test that WebSocket only receives events for subscribed topics."""
    pass