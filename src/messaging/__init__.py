"""
Messaging layer for OpenEASD (Layer 7).

This module provides ZeroMQ-based inter-layer communication with Pub/Sub patterns
for real-time event broadcasting.

Components:
- EventBus: Central Pub/Sub broker
- EventPublisher: Type-safe event publishing interface
- EventSubscriber: Non-blocking event subscription
- Event schemas: Dataclasses for all event types

Usage:
    from src.messaging import EventBus, EventPublisher, EventSubscriber

    # Start event bus
    bus = EventBus()
    bus.start()

    # Publish events
    publisher = EventPublisher(bus)
    publisher.publish_scan_started(...)

    # Subscribe to events
    subscriber = EventSubscriber(bus.ipc_path, topics=["scan.*"])
    event = subscriber.poll(timeout_ms=1000)
"""

from src.messaging.bus import EventBus
from src.messaging.publisher import EventPublisher
from src.messaging.subscriber import EventSubscriber
from src.messaging.manager import EventBusManager
from src.messaging.events import (
    EventType,
    BaseEvent,
    ScanStartedEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
    ToolStartedEvent,
    ToolCompletedEvent,
    ToolFailedEvent,
    FindingDiscoveredEvent,
    AlertCreatedEvent,
    AnalysisStartedEvent,
    AnalysisCompletedEvent,
    AnalysisFailedEvent
)

__all__ = [
    # Core components
    'EventBus',
    'EventPublisher',
    'EventSubscriber',
    'EventBusManager',

    # Event types
    'EventType',
    'BaseEvent',

    # Scan events
    'ScanStartedEvent',
    'ScanCompletedEvent',
    'ScanFailedEvent',

    # Tool events
    'ToolStartedEvent',
    'ToolCompletedEvent',
    'ToolFailedEvent',

    # Finding/Alert events
    'FindingDiscoveredEvent',
    'AlertCreatedEvent',

    # Analysis events
    'AnalysisStartedEvent',
    'AnalysisCompletedEvent',
    'AnalysisFailedEvent',
]
