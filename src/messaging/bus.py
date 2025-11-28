"""
ZeroMQ Event Bus for inter-layer communication.

This module implements a centralized Pub/Sub event bus using ZeroMQ.
"""

import zmq
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class EventBus:
    """
    Central ZeroMQ Pub/Sub event bus for OpenEASD.

    Architecture:
    - Single PUB socket binds to IPC endpoint
    - Multiple SUB sockets connect to broker
    - Topic-based filtering (e.g., "scan.*", "tool.*", "finding.*")
    - Embedded: spawns with API/CLI, auto-cleanup on shutdown

    Usage:
        bus = EventBus()
        bus.start()

        # Publish events
        bus.publish("scan.started", {"scan_id": "123", "domain": "example.com"})

        # Cleanup
        bus.stop()
    """

    def __init__(
        self,
        ipc_path: str = "/tmp/openeasd-events.ipc",
        high_water_mark: int = 1000,
        linger_ms: int = 1000,
        send_timeout_ms: int = 5000
    ):
        """
        Initialize event bus.

        Args:
            ipc_path: IPC socket path for event bus
            high_water_mark: Max queued messages before blocking
            linger_ms: Time to wait for pending messages on shutdown
            send_timeout_ms: Publisher send timeout
        """
        self.ipc_path = ipc_path
        self.high_water_mark = high_water_mark
        self.linger_ms = linger_ms
        self.send_timeout_ms = send_timeout_ms

        self.context: Optional[zmq.Context] = None
        self.socket: Optional[zmq.Socket] = None
        self._is_running = False

    def start(self) -> None:
        """
        Start the event bus and bind to IPC socket.

        Raises:
            RuntimeError: If bus is already running
            zmq.ZMQError: If socket binding fails
        """
        if self._is_running:
            raise RuntimeError("EventBus is already running")

        # Create ZMQ context
        self.context = zmq.Context()

        # Create PUB socket
        self.socket = self.context.socket(zmq.PUB)

        # Configure socket options
        self.socket.setsockopt(zmq.SNDHWM, self.high_water_mark)
        self.socket.setsockopt(zmq.LINGER, self.linger_ms)
        self.socket.setsockopt(zmq.SNDTIMEO, self.send_timeout_ms)

        # Remove existing IPC file if present
        ipc_file = Path(self.ipc_path)
        if ipc_file.exists():
            logger.warning(f"Removing existing IPC socket: {self.ipc_path}")
            ipc_file.unlink()

        # Bind to IPC endpoint
        endpoint = f"ipc://{self.ipc_path}"
        self.socket.bind(endpoint)

        self._is_running = True
        logger.info(f"EventBus started on {endpoint}")

    def stop(self) -> None:
        """
        Stop the event bus and cleanup resources.

        This closes the socket, terminates the context, and removes
        the IPC socket file.
        """
        if not self._is_running:
            logger.warning("EventBus is not running")
            return

        # Close socket
        if self.socket:
            self.socket.close()
            self.socket = None

        # Terminate context
        if self.context:
            self.context.term()
            self.context = None

        # Remove IPC socket file
        ipc_file = Path(self.ipc_path)
        if ipc_file.exists():
            try:
                ipc_file.unlink()
                logger.debug(f"Removed IPC socket: {self.ipc_path}")
            except Exception as e:
                logger.error(f"Failed to remove IPC socket: {e}")

        self._is_running = False
        logger.info("EventBus stopped")

    def publish(self, topic: str, message: bytes) -> None:
        """
        Publish a message to a topic.

        Args:
            topic: Topic name (e.g., "scan.started", "tool.completed")
            message: Message bytes (typically JSON-serialized)

        Raises:
            RuntimeError: If bus is not running
            zmq.ZMQError: If message cannot be sent
        """
        if not self._is_running or not self.socket:
            raise RuntimeError("EventBus is not running")

        # Send multipart message: [topic, message]
        self.socket.send_multipart([topic.encode('utf-8'), message])
        logger.debug(f"Published to topic '{topic}': {len(message)} bytes")

    @property
    def is_running(self) -> bool:
        """Check if event bus is running."""
        return self._is_running

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False
