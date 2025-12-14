"""
Messaging Layer Configuration.

Centralized configuration for ZeroMQ settings.
Loads settings from the unified config.yaml with environment variable overrides.

Author: Rathnakara G N
Company: Cybersecify
Updated: December 2025 - Integrated with unified config
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class MessagingConfig:
    """Configuration for ZeroMQ messaging."""

    # PUSH/PULL addresses
    push_address: str = "tcp://127.0.0.1:5555"
    pull_address: str = "tcp://127.0.0.1:5555"

    # Timeouts (milliseconds)
    send_timeout: int = 5000
    recv_timeout: int = 1000

    # High water mark (queue size limit)
    high_water_mark: int = 1000

    @classmethod
    def from_config(cls) -> "MessagingConfig":
        """
        Load configuration from unified config system.

        Priority: Environment variables > config.yaml > defaults
        """
        from src.utils.config import Config

        try:
            config = Config()
            return cls(
                push_address=config.get(
                    'messaging.push_address',
                    os.getenv("ZMQ_PUSH_ADDRESS", "tcp://127.0.0.1:5555")
                ),
                pull_address=config.get(
                    'messaging.pull_address',
                    os.getenv("ZMQ_PULL_ADDRESS", "tcp://127.0.0.1:5555")
                ),
                send_timeout=config.get(
                    'messaging.send_timeout',
                    int(os.getenv("ZMQ_SEND_TIMEOUT", "5000"))
                ),
                recv_timeout=config.get(
                    'messaging.recv_timeout',
                    int(os.getenv("ZMQ_RECV_TIMEOUT", "1000"))
                ),
                high_water_mark=config.get(
                    'messaging.high_water_mark',
                    int(os.getenv("ZMQ_HIGH_WATER_MARK", "1000"))
                ),
            )
        except Exception:
            # Fall back to env-only config if Config fails
            return cls.from_env()

    @classmethod
    def from_env(cls) -> "MessagingConfig":
        """Load configuration from environment variables only (fallback)."""
        return cls(
            push_address=os.getenv("ZMQ_PUSH_ADDRESS", "tcp://127.0.0.1:5555"),
            pull_address=os.getenv("ZMQ_PULL_ADDRESS", "tcp://127.0.0.1:5555"),
            send_timeout=int(os.getenv("ZMQ_SEND_TIMEOUT", "5000")),
            recv_timeout=int(os.getenv("ZMQ_RECV_TIMEOUT", "1000")),
            high_water_mark=int(os.getenv("ZMQ_HIGH_WATER_MARK", "1000")),
        )


# Global config instance
_config: Optional[MessagingConfig] = None


def get_messaging_config() -> MessagingConfig:
    """Get messaging configuration singleton."""
    global _config
    if _config is None:
        _config = MessagingConfig.from_config()
    return _config


def reset_messaging_config() -> None:
    """Reset the config singleton (useful for testing)."""
    global _config
    _config = None
