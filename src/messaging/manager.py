"""
Global EventBus manager for OpenEASD.

Provides singleton access to event bus and publisher.
"""

from typing import Optional
from src.messaging.bus import EventBus
from src.messaging.publisher import EventPublisher


class EventBusManager:
    """
    Singleton manager for global EventBus and EventPublisher.

    Ensures only one EventBus instance is running at a time.
    """

    _instance: Optional['EventBusManager'] = None
    _bus: Optional[EventBus] = None
    _publisher: Optional[EventPublisher] = None
    _ipc_path: str = "/tmp/openeasd-events.ipc"

    def __new__(cls):
        """Ensure singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_bus(cls) -> Optional[EventBus]:
        """Get the global event bus instance."""
        return cls._bus

    @classmethod
    def get_publisher(cls) -> Optional[EventPublisher]:
        """Get the global event publisher instance."""
        return cls._publisher

    @classmethod
    def start(cls, ipc_path: str = "/tmp/openeasd-events.ipc") -> EventPublisher:
        """
        Start the global event bus.

        Args:
            ipc_path: Path to IPC socket

        Returns:
            EventPublisher instance

        Raises:
            RuntimeError: If bus is already running
        """
        if cls._bus is not None and cls._bus.is_running:
            return cls._publisher  # Already running, return existing publisher

        cls._ipc_path = ipc_path

        # Create and start bus
        cls._bus = EventBus(ipc_path=ipc_path)
        cls._bus.start()

        # Create publisher
        cls._publisher = EventPublisher(cls._bus)

        return cls._publisher

    @classmethod
    def stop(cls):
        """Stop the global event bus."""
        if cls._bus is not None:
            cls._bus.stop()
            cls._bus = None
            cls._publisher = None

    @classmethod
    def is_running(cls) -> bool:
        """Check if event bus is running."""
        return cls._bus is not None and cls._bus.is_running

    @classmethod
    def get_ipc_path(cls) -> str:
        """Get the IPC path."""
        return cls._ipc_path
