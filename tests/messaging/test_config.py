"""
Tests for messaging configuration.
"""

import os
import pytest
from unittest.mock import patch

from src.messaging.config import MessagingConfig, get_messaging_config


class TestMessagingConfig:
    """Tests for MessagingConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MessagingConfig()

        assert config.push_address == "tcp://127.0.0.1:5555"
        assert config.pull_address == "tcp://127.0.0.1:5555"
        assert config.send_timeout == 5000
        assert config.recv_timeout == 1000
        assert config.high_water_mark == 1000

    def test_custom_values(self):
        """Test configuration with custom values."""
        config = MessagingConfig(
            push_address="tcp://192.168.1.1:6666",
            pull_address="tcp://192.168.1.1:6666",
            send_timeout=10000,
            recv_timeout=2000,
            high_water_mark=500
        )

        assert config.push_address == "tcp://192.168.1.1:6666"
        assert config.pull_address == "tcp://192.168.1.1:6666"
        assert config.send_timeout == 10000
        assert config.recv_timeout == 2000
        assert config.high_water_mark == 500

    def test_from_env_defaults(self):
        """Test from_env with no environment variables set."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear any existing env vars
            for key in ['ZMQ_PUSH_ADDRESS', 'ZMQ_PULL_ADDRESS', 'ZMQ_SEND_TIMEOUT',
                       'ZMQ_RECV_TIMEOUT', 'ZMQ_HIGH_WATER_MARK']:
                os.environ.pop(key, None)

            config = MessagingConfig.from_env()

            assert config.push_address == "tcp://127.0.0.1:5555"
            assert config.pull_address == "tcp://127.0.0.1:5555"
            assert config.send_timeout == 5000
            assert config.recv_timeout == 1000
            assert config.high_water_mark == 1000

    def test_from_env_custom(self):
        """Test from_env with custom environment variables."""
        env_vars = {
            'ZMQ_PUSH_ADDRESS': 'tcp://10.0.0.1:7777',
            'ZMQ_PULL_ADDRESS': 'tcp://10.0.0.1:7777',
            'ZMQ_SEND_TIMEOUT': '15000',
            'ZMQ_RECV_TIMEOUT': '3000',
            'ZMQ_HIGH_WATER_MARK': '2000'
        }

        with patch.dict(os.environ, env_vars, clear=False):
            config = MessagingConfig.from_env()

            assert config.push_address == "tcp://10.0.0.1:7777"
            assert config.pull_address == "tcp://10.0.0.1:7777"
            assert config.send_timeout == 15000
            assert config.recv_timeout == 3000
            assert config.high_water_mark == 2000

    def test_from_env_partial(self):
        """Test from_env with partial environment variables."""
        env_vars = {
            'ZMQ_PUSH_ADDRESS': 'tcp://custom:8888'
        }

        with patch.dict(os.environ, env_vars, clear=False):
            # Clear other vars
            for key in ['ZMQ_PULL_ADDRESS', 'ZMQ_SEND_TIMEOUT',
                       'ZMQ_RECV_TIMEOUT', 'ZMQ_HIGH_WATER_MARK']:
                os.environ.pop(key, None)

            config = MessagingConfig.from_env()

            assert config.push_address == "tcp://custom:8888"
            # Others should be defaults
            assert config.recv_timeout == 1000


class TestGetMessagingConfig:
    """Tests for get_messaging_config singleton."""

    def test_returns_config(self):
        """Test that get_messaging_config returns a config instance."""
        config = get_messaging_config()
        assert isinstance(config, MessagingConfig)

    def test_singleton_behavior(self):
        """Test that get_messaging_config returns the same instance."""
        config1 = get_messaging_config()
        config2 = get_messaging_config()
        # They should be the same object (singleton)
        assert config1 is config2
