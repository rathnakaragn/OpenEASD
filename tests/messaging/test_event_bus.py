"""
Tests for EventBus.
"""

import pytest
import time
from pathlib import Path
from src.messaging.bus import EventBus


def test_eventbus_init():
    """Test EventBus initialization."""
    bus = EventBus(ipc_path="/tmp/test-events.ipc")
    assert bus.ipc_path == "/tmp/test-events.ipc"
    assert bus.high_water_mark == 1000
    assert not bus.is_running


def test_eventbus_start_stop():
    """Test EventBus start and stop."""
    bus = EventBus(ipc_path="/tmp/test-events-start.ipc")

    # Start bus
    bus.start()
    assert bus.is_running
    assert bus.socket is not None
    assert bus.context is not None

    # Stop bus
    bus.stop()
    assert not bus.is_running
    assert bus.socket is None
    assert bus.context is None


def test_eventbus_start_twice_raises_error():
    """Test that starting bus twice raises error."""
    bus = EventBus(ipc_path="/tmp/test-events-twice.ipc")
    bus.start()

    with pytest.raises(RuntimeError, match="already running"):
        bus.start()

    bus.stop()


def test_eventbus_publish():
    """Test publishing messages to event bus."""
    bus = EventBus(ipc_path="/tmp/test-events-publish.ipc")
    bus.start()

    # Publish message
    bus.publish("test.topic", b"test message")

    bus.stop()


def test_eventbus_publish_without_start_raises_error():
    """Test that publishing without starting raises error."""
    bus = EventBus(ipc_path="/tmp/test-events-nostart.ipc")

    with pytest.raises(RuntimeError, match="not running"):
        bus.publish("test.topic", b"test message")


def test_eventbus_context_manager():
    """Test EventBus as context manager."""
    with EventBus(ipc_path="/tmp/test-events-context.ipc") as bus:
        assert bus.is_running
        bus.publish("test.topic", b"test message")

    assert not bus.is_running


def test_eventbus_removes_ipc_file():
    """Test that EventBus removes IPC socket file on stop."""
    ipc_path = "/tmp/test-events-cleanup.ipc"
    bus = EventBus(ipc_path=ipc_path)

    bus.start()
    assert Path(ipc_path).exists()

    bus.stop()
    assert not Path(ipc_path).exists()


def test_eventbus_removes_existing_ipc_file():
    """Test that EventBus removes existing IPC file on start."""
    ipc_path = "/tmp/test-events-existing.ipc"

    # Create existing file
    Path(ipc_path).touch()
    assert Path(ipc_path).exists()

    # Start bus (should remove existing file)
    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    # Stop bus
    bus.stop()
    assert not Path(ipc_path).exists()
