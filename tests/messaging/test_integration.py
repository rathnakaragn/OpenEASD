"""
Integration tests for the messaging layer.

Tests the complete pub/sub flow: EventBus + EventPublisher + EventSubscriber.
"""

import pytest
import time
import json
from src.messaging import EventBus, EventPublisher, EventSubscriber


def test_pubsub_single_message():
    """Test publishing and receiving a single message."""
    ipc_path = "/tmp/test-pubsub-single.ipc"

    # Start event bus
    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        # Create subscriber
        subscriber = EventSubscriber(ipc_path, topics=["test"])

        # Give subscriber time to connect
        time.sleep(0.1)

        # Publish message
        message = json.dumps({"event_type": "test.event", "data": "hello"}).encode()
        bus.publish("test", message)

        # Poll for message
        event = subscriber.poll(timeout_ms=1000)
        assert event is not None
        assert event["event_type"] == "test.event"
        assert event["data"] == "hello"

        # Cleanup
        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_pubsub_multiple_messages():
    """Test publishing and receiving multiple messages."""
    ipc_path = "/tmp/test-pubsub-multiple.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        subscriber = EventSubscriber(ipc_path, topics=["test"])
        time.sleep(0.1)

        # Publish multiple messages
        for i in range(5):
            message = json.dumps({"event_type": "test.event", "index": i}).encode()
            bus.publish("test", message)

        # Receive all messages
        events = []
        for _ in range(5):
            event = subscriber.poll(timeout_ms=1000)
            if event:
                events.append(event)

        assert len(events) == 5
        for i, event in enumerate(events):
            assert event["index"] == i

        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_pubsub_topic_filtering():
    """Test that subscribers only receive messages for their topics."""
    ipc_path = "/tmp/test-pubsub-filter.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        # Subscribe only to "scan.*"
        subscriber = EventSubscriber(ipc_path, topics=["scan.*"])
        time.sleep(0.1)

        # Publish to different topics
        scan_msg = json.dumps({"event_type": "scan.started"}).encode()
        tool_msg = json.dumps({"event_type": "tool.started"}).encode()

        bus.publish("scan.started", scan_msg)
        bus.publish("tool.started", tool_msg)

        # Should only receive scan message
        event = subscriber.poll(timeout_ms=1000)
        assert event is not None
        assert event["event_type"] == "scan.started"

        # Should not receive tool message
        event = subscriber.poll(timeout_ms=500)
        assert event is None

        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_eventpublisher_with_subscriber():
    """Test EventPublisher with EventSubscriber integration."""
    ipc_path = "/tmp/test-publisher-subscriber.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        publisher = EventPublisher(bus)
        subscriber = EventSubscriber(ipc_path, topics=["scan.*", "tool.*"])
        time.sleep(0.1)

        # Publish scan started event
        publisher.publish_scan_started(
            scan_id="scan-123",
            domain="example.com",
            scan_type="passive",
            tool_name="subfinder"
        )

        # Receive event
        event = subscriber.poll(timeout_ms=1000)
        assert event is not None
        assert event["event_type"] == "scan.started"
        assert event["scan_id"] == "scan-123"
        assert event["domain"] == "example.com"
        assert event["scan_type"] == "passive"

        # Publish tool completed event
        publisher.publish_tool_completed(
            scan_id="scan-123",
            tool_name="subfinder",
            domain="example.com",
            results_count=42,
            duration_seconds=15.3
        )

        # Receive event
        event = subscriber.poll(timeout_ms=1000)
        assert event is not None
        assert event["event_type"] == "scan.tool.completed"
        assert event["tool_name"] == "subfinder"
        assert event["results_count"] == 42
        assert event["duration_seconds"] == 15.3

        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_multiple_subscribers():
    """Test that multiple subscribers can receive the same event."""
    ipc_path = "/tmp/test-multi-subscribers.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        # Create two subscribers
        sub1 = EventSubscriber(ipc_path, topics=["test"])
        sub2 = EventSubscriber(ipc_path, topics=["test"])
        time.sleep(0.1)

        # Publish one message
        message = json.dumps({"event_type": "test.event", "data": "broadcast"}).encode()
        bus.publish("test", message)

        # Both subscribers should receive it
        event1 = sub1.poll(timeout_ms=1000)
        event2 = sub2.poll(timeout_ms=1000)

        assert event1 is not None
        assert event2 is not None
        assert event1["data"] == "broadcast"
        assert event2["data"] == "broadcast"

        sub1.unsubscribe()
        sub2.unsubscribe()

    finally:
        bus.stop()


def test_subscriber_poll_batch():
    """Test batch polling for multiple events."""
    ipc_path = "/tmp/test-poll-batch.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        subscriber = EventSubscriber(ipc_path, topics=["test"])
        time.sleep(0.1)

        # Publish 10 messages
        for i in range(10):
            message = json.dumps({"event_type": "test.event", "index": i}).encode()
            bus.publish("test", message)

        # Poll batch
        events = subscriber.poll_batch(max_events=10, timeout_ms=100)

        assert len(events) == 10
        for i, event in enumerate(events):
            assert event["index"] == i

        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_subscriber_subscribe_unsubscribe_topic():
    """Test dynamic topic subscription/unsubscription."""
    ipc_path = "/tmp/test-dynamic-topics.ipc"

    bus = EventBus(ipc_path=ipc_path)
    bus.start()

    try:
        # Start with one topic
        subscriber = EventSubscriber(ipc_path, topics=["scan.*"])
        time.sleep(0.1)

        # Publish to scan topic
        scan_msg = json.dumps({"event_type": "scan.started"}).encode()
        bus.publish("scan.started", scan_msg)

        event = subscriber.poll(timeout_ms=1000)
        assert event is not None

        # Add tool topic
        subscriber.subscribe_to_topic("tool.*")
        time.sleep(0.05)

        # Publish to tool topic
        tool_msg = json.dumps({"event_type": "tool.started"}).encode()
        bus.publish("tool.started", tool_msg)

        event = subscriber.poll(timeout_ms=1000)
        assert event is not None
        assert event["event_type"] == "tool.started"

        # Unsubscribe from scan topic
        subscriber.unsubscribe_from_topic("scan.*")
        time.sleep(0.05)

        # Publish to scan topic (should not receive)
        bus.publish("scan.started", scan_msg)
        event = subscriber.poll(timeout_ms=500)
        assert event is None

        subscriber.unsubscribe()

    finally:
        bus.stop()


def test_context_manager():
    """Test EventBus and EventSubscriber as context managers."""
    ipc_path = "/tmp/test-context-managers.ipc"

    with EventBus(ipc_path=ipc_path) as bus:
        assert bus.is_running

        with EventSubscriber(ipc_path, topics=["test"]) as subscriber:
            time.sleep(0.1)

            # Publish and receive
            message = json.dumps({"event_type": "test.event"}).encode()
            bus.publish("test", message)

            event = subscriber.poll(timeout_ms=1000)
            assert event is not None

    # Both should be cleaned up
    assert not bus.is_running
