"""
WebSocket endpoint for real-time event streaming.

Allows API clients to subscribe to scan/tool/analysis events via WebSocket.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import List, Optional
import asyncio
import json
from src.messaging.manager import EventBusManager
from src.messaging.subscriber import EventSubscriber
from src.api.dependencies import verify_api_key_sync


router = APIRouter()


@router.websocket("/events")
async def websocket_events(
    websocket: WebSocket,
    api_key: Optional[str] = Query(None, description="API key for authentication"),
    topics: Optional[str] = Query(None, description="Comma-separated topics (e.g., 'scan.*,tool.*')")
):
    """
    WebSocket endpoint for real-time event streaming (Authenticated).

    Requires API key authentication via 'api_key' query parameter.

    Subscribe to events by topic patterns:
    - scan.*: All scan events
    - tool.*: All tool events
    - finding.*: Finding discovery events
    - analysis.*: Analysis events
    - scan.{scan_id}.*: Events for specific scan

    Example usage:
        ws://localhost:8000/api/v1/events?api_key=YOUR_API_KEY&topics=scan.*,finding.*

    The WebSocket will receive JSON messages for each matching event.
    """
    # Authenticate API key before accepting connection
    is_valid, api_key_info, error = verify_api_key_sync(api_key)

    if not is_valid:
        await websocket.accept()
        await websocket.send_json({
            "error": f"Authentication failed: {error}",
            "type": "error"
        })
        await websocket.close(code=1008, reason="Authentication failed")
        return

    # Accept connection after authentication
    await websocket.accept()

    # Parse topics
    if topics:
        topic_list = [t.strip() for t in topics.split(',')]
    else:
        # Default to all event types
        topic_list = ["scan.*", "tool.*", "finding.*", "analysis.*"]

    # Check if EventBus is running
    if not EventBusManager.is_running():
        await websocket.send_json({
            "error": "EventBus is not running. Real-time events are unavailable."
        })
        await websocket.close()
        return

    # Create subscriber
    ipc_path = EventBusManager.get_ipc_path()
    subscriber = None

    try:
        subscriber = EventSubscriber(ipc_path, topics=topic_list)

        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "topics": topic_list,
            "message": "WebSocket connected. Listening for events..."
        })

        # Event streaming loop
        while True:
            # Poll for events (non-blocking with short timeout)
            event = subscriber.poll(timeout_ms=100)

            if event:
                # Send event to WebSocket client
                await websocket.send_json(event)

            # Also check for incoming WebSocket messages (for client disconnect detection)
            try:
                # Very short timeout to check if client closed connection
                message = await asyncio.wait_for(websocket.receive_text(), timeout=0.01)

                # Client can send commands (future: subscribe/unsubscribe to topics)
                try:
                    command = json.loads(message)
                    if command.get('type') == 'ping':
                        await websocket.send_json({"type": "pong"})
                except json.JSONDecodeError:
                    pass

            except asyncio.TimeoutError:
                # No message from client - continue polling
                pass
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({
                "error": f"WebSocket error: {str(e)}"
            })
        except:
            pass
    finally:
        # Clean up subscriber
        if subscriber:
            subscriber.unsubscribe()

        try:
            await websocket.close()
        except:
            pass


@router.get("/events/status")
async def events_status():
    """
    Get status of the event streaming service.

    Returns:
        Status information including whether EventBus is running
    """
    return {
        "event_bus_running": EventBusManager.is_running(),
        "ipc_path": EventBusManager.get_ipc_path(),
        "websocket_endpoint": "/api/v1/events",
        "supported_topics": [
            "scan.*",
            "scan.{scan_id}.*",
            "tool.*",
            "finding.*",
            "analysis.*"
        ],
        "example_url": "ws://localhost:8000/api/v1/events?topics=scan.*,finding.*"
    }
