"""
Event subscriber interface for the messaging layer.

Provides non-blocking subscription to events from the ZeroMQ event bus.
"""

import zmq
import json
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class EventSubscriber:
    """
    Subscribes to events from ZeroMQ event bus.

    Non-blocking with timeout support for use in CLI progress display
    and API WebSocket streaming.

    Usage:
        # CLI usage - subscribe to all scan events
        subscriber = EventSubscriber(
            ipc_path="/tmp/openeasd-events.ipc",
            topics=["scan.*", "tool.*", "finding.*"]
        )

        while scan_running:
            event = subscriber.poll(timeout_ms=100)
            if event:
                print(f"Event: {event['event_type']}")

        subscriber.unsubscribe()
    """

    def __init__(
        self,
        ipc_path: str,
        topics: List[str],
        recv_timeout_ms: int = 1000
    ):
        """
        Initialize event subscriber.

        Args:
            ipc_path: IPC socket path to connect to
            topics: List of topics to subscribe to (e.g., ["scan.*", "tool.*"])
            recv_timeout_ms: Receive timeout in milliseconds
        """
        self.ipc_path = ipc_path
        self.topics = topics
        self.recv_timeout_ms = recv_timeout_ms

        # Initialize ZMQ context and socket
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.SUB)

        # Connect to event bus
        endpoint = f"ipc://{self.ipc_path}"
        self.socket.connect(endpoint)
        logger.debug(f"EventSubscriber connected to {endpoint}")

        # Subscribe to topics
        for topic in self.topics:
            if topic.endswith(".*"):
                # Wildcard subscription: subscribe to prefix
                prefix = topic[:-2]  # Remove ".*"
                self.socket.setsockopt(zmq.SUBSCRIBE, prefix.encode('utf-8'))
                logger.debug(f"Subscribed to topic prefix: {prefix}")
            else:
                # Exact topic subscription
                self.socket.setsockopt(zmq.SUBSCRIBE, topic.encode('utf-8'))
                logger.debug(f"Subscribed to exact topic: {topic}")

        # Set receive timeout
        self.socket.setsockopt(zmq.RCVTIMEO, recv_timeout_ms)

    def poll(self, timeout_ms: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Poll for next event (non-blocking).

        Args:
            timeout_ms: Timeout in milliseconds (overrides constructor value if provided)

        Returns:
            Event dictionary if available, None if timeout

        Raises:
            zmq.ZMQError: If socket error occurs
            json.JSONDecodeError: If event cannot be deserialized
        """
        # Override timeout if provided
        if timeout_ms is not None:
            self.socket.setsockopt(zmq.RCVTIMEO, timeout_ms)

        try:
            # Check if message is available
            if self.socket.poll(timeout_ms or self.recv_timeout_ms, zmq.POLLIN):
                # Receive multipart message: [topic, message]
                topic, message = self.socket.recv_multipart()

                # Deserialize message
                event_data = json.loads(message.decode('utf-8'))

                # Add topic to event data for debugging
                event_data['_topic'] = topic.decode('utf-8')

                logger.debug(f"Received event from topic '{topic.decode()}': {event_data.get('event_type')}")
                return event_data

            return None

        except zmq.Again:
            # Timeout - no message available
            return None
        except Exception as e:
            logger.error(f"Error receiving event: {e}", exc_info=True)
            raise

    def poll_batch(
        self,
        max_events: int = 10,
        timeout_ms: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Poll for multiple events in a batch.

        Useful for processing bursts of events efficiently.

        Args:
            max_events: Maximum number of events to retrieve
            timeout_ms: Timeout per event in milliseconds

        Returns:
            List of event dictionaries (may be empty)
        """
        events = []
        for _ in range(max_events):
            event = self.poll(timeout_ms=timeout_ms)
            if event:
                events.append(event)
            else:
                break  # No more events available
        return events

    def subscribe_to_topic(self, topic: str) -> None:
        """
        Subscribe to an additional topic.

        Args:
            topic: Topic to subscribe to (e.g., "scan.123.*")
        """
        if topic.endswith(".*"):
            prefix = topic[:-2]
            self.socket.setsockopt(zmq.SUBSCRIBE, prefix.encode('utf-8'))
            logger.debug(f"Subscribed to additional topic prefix: {prefix}")
        else:
            self.socket.setsockopt(zmq.SUBSCRIBE, topic.encode('utf-8'))
            logger.debug(f"Subscribed to additional exact topic: {topic}")

        if topic not in self.topics:
            self.topics.append(topic)

    def unsubscribe_from_topic(self, topic: str) -> None:
        """
        Unsubscribe from a topic.

        Args:
            topic: Topic to unsubscribe from
        """
        if topic.endswith(".*"):
            prefix = topic[:-2]
            self.socket.setsockopt(zmq.UNSUBSCRIBE, prefix.encode('utf-8'))
            logger.debug(f"Unsubscribed from topic prefix: {prefix}")
        else:
            self.socket.setsockopt(zmq.UNSUBSCRIBE, topic.encode('utf-8'))
            logger.debug(f"Unsubscribed from exact topic: {topic}")

        if topic in self.topics:
            self.topics.remove(topic)

    def unsubscribe(self) -> None:
        """
        Unsubscribe from all topics and cleanup resources.

        Closes the socket and terminates the context.
        """
        if self.socket:
            # Unsubscribe from all topics
            for topic in self.topics:
                try:
                    if topic.endswith(".*"):
                        prefix = topic[:-2]
                        self.socket.setsockopt(zmq.UNSUBSCRIBE, prefix.encode('utf-8'))
                    else:
                        self.socket.setsockopt(zmq.UNSUBSCRIBE, topic.encode('utf-8'))
                except Exception as e:
                    logger.warning(f"Error unsubscribing from {topic}: {e}")

            # Close socket
            self.socket.close()
            self.socket = None
            logger.debug("EventSubscriber socket closed")

        if self.context:
            # Terminate context
            self.context.term()
            self.context = None
            logger.debug("EventSubscriber context terminated")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.unsubscribe()
        return False
