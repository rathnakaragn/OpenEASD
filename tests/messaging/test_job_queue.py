"""
Tests for JobQueue - ZeroMQ job queue with database persistence.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import zmq

from src.messaging.job_queue import JobQueue, get_job_queue
from src.messaging.config import MessagingConfig


@pytest.fixture
def mock_config():
    """Create a mock messaging config."""
    return MessagingConfig(
        push_address="tcp://127.0.0.1:5555",
        pull_address="tcp://127.0.0.1:5555",
        send_timeout=5000,
        recv_timeout=1000,
        high_water_mark=1000
    )


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    return MagicMock()


@pytest.fixture
def job_queue(mock_config, mock_db_manager):
    """Create a JobQueue instance with mocks."""
    queue = JobQueue(config=mock_config, db_manager=mock_db_manager)
    return queue


class TestJobQueueInit:
    """Tests for JobQueue initialization."""

    def test_init_with_config(self, mock_config, mock_db_manager):
        """Test initialization with config and db_manager."""
        queue = JobQueue(config=mock_config, db_manager=mock_db_manager)

        assert queue.config == mock_config
        assert queue.db_manager == mock_db_manager
        assert queue.push_socket is None
        assert queue.pull_socket is None

    def test_init_without_config(self, mock_db_manager):
        """Test initialization without config uses default."""
        queue = JobQueue(db_manager=mock_db_manager)

        assert queue.config is not None
        assert queue.db_manager == mock_db_manager

    def test_init_without_db_manager(self, mock_config):
        """Test initialization without db_manager."""
        queue = JobQueue(config=mock_config)

        assert queue.config == mock_config
        assert queue.db_manager is None


class TestSetDbManager:
    """Tests for set_db_manager method."""

    def test_set_db_manager(self, job_queue, mock_db_manager):
        """Test setting database manager."""
        new_db = MagicMock()
        job_queue.set_db_manager(new_db)

        assert job_queue.db_manager == new_db


class TestSetWorkerId:
    """Tests for set_worker_id method."""

    def test_set_worker_id(self, job_queue):
        """Test setting worker ID."""
        job_queue.set_worker_id("worker-123")

        assert job_queue._worker_id == "worker-123"


class TestConnectPush:
    """Tests for connect_push method."""

    @patch('src.messaging.job_queue.zmq.Context')
    def test_connect_push_creates_socket(self, mock_context_class, mock_config):
        """Test connect_push creates and configures PUSH socket."""
        mock_context = MagicMock()
        mock_socket = MagicMock()
        mock_context_class.instance.return_value = mock_context
        mock_context.socket.return_value = mock_socket

        queue = JobQueue(config=mock_config)
        queue.context = mock_context
        queue.connect_push()

        mock_context.socket.assert_called_once_with(zmq.PUSH)
        mock_socket.setsockopt.assert_any_call(zmq.SNDTIMEO, 5000)
        mock_socket.setsockopt.assert_any_call(zmq.SNDHWM, 1000)
        mock_socket.connect.assert_called_once_with("tcp://127.0.0.1:5555")

    def test_connect_push_idempotent(self, job_queue):
        """Test connect_push doesn't create new socket if already connected."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_queue.connect_push()

        # Should not create new socket
        assert job_queue.push_socket == mock_socket


class TestConnectPull:
    """Tests for connect_pull method."""

    @patch('src.messaging.job_queue.zmq.Context')
    def test_connect_pull_creates_socket(self, mock_context_class, mock_config):
        """Test connect_pull creates and configures PULL socket."""
        mock_context = MagicMock()
        mock_socket = MagicMock()
        mock_context_class.instance.return_value = mock_context
        mock_context.socket.return_value = mock_socket

        queue = JobQueue(config=mock_config)
        queue.context = mock_context
        queue.connect_pull()

        mock_context.socket.assert_called_once_with(zmq.PULL)
        mock_socket.setsockopt.assert_any_call(zmq.RCVTIMEO, 1000)
        mock_socket.setsockopt.assert_any_call(zmq.RCVHWM, 1000)
        mock_socket.bind.assert_called_once_with("tcp://127.0.0.1:5555")

    def test_connect_pull_idempotent(self, job_queue):
        """Test connect_pull doesn't create new socket if already connected."""
        mock_socket = MagicMock()
        job_queue.pull_socket = mock_socket

        job_queue.connect_pull()

        assert job_queue.pull_socket == mock_socket


class TestPushJob:
    """Tests for push_job method."""

    def test_push_job_without_socket_raises(self, job_queue):
        """Test push_job raises error if socket not connected."""
        with pytest.raises(RuntimeError, match="PUSH socket not connected"):
            job_queue.push_job("scan", {"domain": "example.com"})

    def test_push_job_persists_to_database(self, job_queue, mock_db_manager):
        """Test push_job persists job to database first."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_id = job_queue.push_job(
            job_type="scan",
            payload={"domain": "example.com"},
            scan_id="scan-123",
            priority=50
        )

        # Verify job was persisted
        mock_db_manager.create_job.assert_called_once()
        call_kwargs = mock_db_manager.create_job.call_args[1]
        assert call_kwargs['job_type'] == "scan"
        assert call_kwargs['payload'] == {"domain": "example.com"}
        assert call_kwargs['scan_id'] == "scan-123"
        assert call_kwargs['priority'] == 50

    def test_push_job_sends_to_zeromq(self, job_queue, mock_db_manager):
        """Test push_job sends job message to ZeroMQ."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_id = job_queue.push_job("scan", {"domain": "example.com"})

        mock_socket.send_json.assert_called_once()
        sent_job = mock_socket.send_json.call_args[0][0]
        assert sent_job['type'] == "scan"
        assert sent_job['payload'] == {"domain": "example.com"}
        assert 'id' in sent_job
        assert 'submitted_at' in sent_job

    def test_push_job_marks_as_queued(self, job_queue, mock_db_manager):
        """Test push_job marks job as queued after sending."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_id = job_queue.push_job("scan", {"domain": "example.com"})

        mock_db_manager.mark_job_queued.assert_called_once_with(job_id)

    def test_push_job_returns_job_id(self, job_queue, mock_db_manager):
        """Test push_job returns a valid job ID."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_id = job_queue.push_job("scan", {"domain": "example.com"})

        assert job_id is not None
        assert len(job_id) == 36  # UUID format

    def test_push_job_without_db_manager(self, mock_config):
        """Test push_job works without database persistence."""
        queue = JobQueue(config=mock_config)
        mock_socket = MagicMock()
        queue.push_socket = mock_socket

        job_id = queue.push_job("scan", {"domain": "example.com"})

        assert job_id is not None
        mock_socket.send_json.assert_called_once()

    def test_push_job_database_error_raises(self, job_queue, mock_db_manager):
        """Test push_job raises if database persistence fails."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket
        mock_db_manager.create_job.side_effect = Exception("DB Error")

        with pytest.raises(Exception, match="DB Error"):
            job_queue.push_job("scan", {"domain": "example.com"})

    def test_push_job_zeromq_timeout(self, job_queue, mock_db_manager):
        """Test push_job handles ZeroMQ timeout."""
        mock_socket = MagicMock()
        mock_socket.send_json.side_effect = zmq.Again()
        job_queue.push_socket = mock_socket

        with pytest.raises(zmq.Again):
            job_queue.push_job("scan", {"domain": "example.com"})

        # Job should still be in database (pending status for recovery)
        mock_db_manager.create_job.assert_called_once()


class TestPullJob:
    """Tests for pull_job method."""

    def test_pull_job_without_socket_raises(self, job_queue):
        """Test pull_job raises error if socket not connected."""
        with pytest.raises(RuntimeError, match="PULL socket not connected"):
            job_queue.pull_job()

    def test_pull_job_returns_message(self, job_queue, mock_db_manager):
        """Test pull_job returns job message."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {'domain': 'example.com'}
        }
        job_queue.pull_socket = mock_socket
        mock_db_manager.claim_job.return_value = True

        job = job_queue.pull_job()

        assert job['id'] == 'job-123'
        assert job['type'] == 'scan'

    def test_pull_job_claims_in_database(self, job_queue, mock_db_manager):
        """Test pull_job claims job in database."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {}
        }
        job_queue.pull_socket = mock_socket
        job_queue._worker_id = "worker-001"
        mock_db_manager.claim_job.return_value = True

        job_queue.pull_job()

        mock_db_manager.claim_job.assert_called_once_with('job-123', 'worker-001')

    def test_pull_job_already_claimed_returns_none(self, job_queue, mock_db_manager):
        """Test pull_job returns None if job already claimed."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {}
        }
        job_queue.pull_socket = mock_socket
        mock_db_manager.claim_job.return_value = False  # Already claimed

        job = job_queue.pull_job()

        assert job is None

    def test_pull_job_timeout_returns_none(self, job_queue, mock_db_manager):
        """Test pull_job returns None on timeout."""
        mock_socket = MagicMock()
        mock_socket.recv_json.side_effect = zmq.Again()
        job_queue.pull_socket = mock_socket

        job = job_queue.pull_job()

        assert job is None

    def test_pull_job_nonblocking(self, job_queue, mock_db_manager):
        """Test pull_job with non-blocking mode."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {}
        }
        job_queue.pull_socket = mock_socket
        mock_db_manager.claim_job.return_value = True

        job = job_queue.pull_job(block=False)

        mock_socket.recv_json.assert_called_with(flags=zmq.NOBLOCK)

    def test_pull_job_generates_worker_id(self, job_queue, mock_db_manager):
        """Test pull_job generates worker ID if not set."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {}
        }
        job_queue.pull_socket = mock_socket
        job_queue._worker_id = None
        mock_db_manager.claim_job.return_value = True

        job_queue.pull_job()

        # Should have called claim_job with a generated worker ID
        call_args = mock_db_manager.claim_job.call_args[0]
        assert call_args[0] == 'job-123'
        assert call_args[1].startswith('worker-')


class TestCompleteJob:
    """Tests for complete_job method."""

    def test_complete_job_success(self, job_queue, mock_db_manager):
        """Test marking job as completed."""
        mock_db_manager.complete_job.return_value = True

        result = job_queue.complete_job('job-123', success=True)

        assert result is True
        mock_db_manager.complete_job.assert_called_once_with('job-123', True, None)

    def test_complete_job_failed(self, job_queue, mock_db_manager):
        """Test marking job as failed with error message."""
        mock_db_manager.complete_job.return_value = True

        result = job_queue.complete_job(
            'job-123',
            success=False,
            error_message="Connection timeout"
        )

        assert result is True
        mock_db_manager.complete_job.assert_called_once_with(
            'job-123', False, "Connection timeout"
        )

    def test_complete_job_no_db_manager(self, mock_config):
        """Test complete_job returns False without db_manager."""
        queue = JobQueue(config=mock_config)

        result = queue.complete_job('job-123')

        assert result is False

    def test_complete_job_db_error(self, job_queue, mock_db_manager):
        """Test complete_job handles database errors."""
        mock_db_manager.complete_job.side_effect = Exception("DB Error")

        result = job_queue.complete_job('job-123')

        assert result is False


class TestClose:
    """Tests for close method."""

    def test_close_push_socket(self, job_queue):
        """Test closing PUSH socket."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_queue.close()

        mock_socket.close.assert_called_once()
        assert job_queue.push_socket is None

    def test_close_pull_socket(self, job_queue):
        """Test closing PULL socket."""
        mock_socket = MagicMock()
        job_queue.pull_socket = mock_socket

        job_queue.close()

        mock_socket.close.assert_called_once()
        assert job_queue.pull_socket is None

    def test_close_both_sockets(self, job_queue):
        """Test closing both sockets."""
        mock_push = MagicMock()
        mock_pull = MagicMock()
        job_queue.push_socket = mock_push
        job_queue.pull_socket = mock_pull

        job_queue.close()

        mock_push.close.assert_called_once()
        mock_pull.close.assert_called_once()
        assert job_queue.push_socket is None
        assert job_queue.pull_socket is None

    def test_close_no_sockets(self, job_queue):
        """Test close with no sockets connected."""
        # Should not raise
        job_queue.close()


class TestContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_enter(self, job_queue):
        """Test __enter__ returns self."""
        result = job_queue.__enter__()
        assert result is job_queue

    def test_context_manager_exit_closes(self, job_queue):
        """Test __exit__ calls close."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket

        job_queue.__exit__(None, None, None)

        mock_socket.close.assert_called_once()

    def test_context_manager_usage(self, mock_config, mock_db_manager):
        """Test using JobQueue as context manager."""
        with JobQueue(config=mock_config, db_manager=mock_db_manager) as queue:
            assert isinstance(queue, JobQueue)
        # Socket should be None after exiting context


class TestGetJobQueue:
    """Tests for get_job_queue singleton function."""

    def test_get_job_queue_returns_instance(self):
        """Test get_job_queue returns a JobQueue instance."""
        # Reset singleton
        import src.messaging.job_queue as jq_module
        jq_module._job_queue = None

        with patch.object(JobQueue, 'connect_push'):
            queue = get_job_queue()

        assert isinstance(queue, JobQueue)

    def test_get_job_queue_singleton(self):
        """Test get_job_queue returns same instance."""
        import src.messaging.job_queue as jq_module
        jq_module._job_queue = None

        with patch.object(JobQueue, 'connect_push'):
            queue1 = get_job_queue()
            queue2 = get_job_queue()

        assert queue1 is queue2

    def test_get_job_queue_with_db_manager(self):
        """Test get_job_queue sets db_manager."""
        import src.messaging.job_queue as jq_module
        jq_module._job_queue = None

        mock_db = MagicMock()
        with patch.object(JobQueue, 'connect_push'):
            queue = get_job_queue(db_manager=mock_db)

        assert queue.db_manager == mock_db

    def test_get_job_queue_updates_existing_db_manager(self):
        """Test get_job_queue updates db_manager on existing instance."""
        import src.messaging.job_queue as jq_module
        jq_module._job_queue = None

        # First call without db_manager
        with patch.object(JobQueue, 'connect_push'):
            queue1 = get_job_queue()

        assert queue1.db_manager is None

        # Second call with db_manager
        mock_db = MagicMock()
        queue2 = get_job_queue(db_manager=mock_db)

        assert queue1 is queue2  # Same instance
        assert queue2.db_manager == mock_db


class TestPushJobEdgeCases:
    """Additional edge case tests for push_job method."""

    def test_push_job_mark_queued_failure_non_critical(self, job_queue, mock_db_manager):
        """Test push_job continues even if mark_queued fails (non-critical)."""
        mock_socket = MagicMock()
        job_queue.push_socket = mock_socket
        mock_db_manager.mark_job_queued.side_effect = Exception("Mark queued failed")

        # Should not raise - mark_queued failure is non-critical
        job_id = job_queue.push_job("scan", {"domain": "example.com"})

        assert job_id is not None
        mock_socket.send_json.assert_called_once()


class TestPullJobEdgeCases:
    """Additional edge case tests for pull_job method."""

    def test_pull_job_claim_exception_returns_none(self, job_queue, mock_db_manager):
        """Test pull_job returns None if claim_job raises exception."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {}
        }
        job_queue.pull_socket = mock_socket
        mock_db_manager.claim_job.side_effect = Exception("Claim failed")

        job = job_queue.pull_job()

        assert job is None

    def test_pull_job_no_job_id_in_message(self, job_queue, mock_db_manager):
        """Test pull_job handles message without job ID."""
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'type': 'scan',
            'payload': {}
            # No 'id' field
        }
        job_queue.pull_socket = mock_socket

        job = job_queue.pull_job()

        # Should return the message (no claim needed without ID)
        assert job is not None
        assert job['type'] == 'scan'
        # claim_job should not be called when no ID
        mock_db_manager.claim_job.assert_not_called()

    def test_pull_job_without_db_manager(self, mock_config):
        """Test pull_job works without database persistence."""
        queue = JobQueue(config=mock_config)
        mock_socket = MagicMock()
        mock_socket.recv_json.return_value = {
            'id': 'job-123',
            'type': 'scan',
            'payload': {'domain': 'example.com'}
        }
        queue.pull_socket = mock_socket

        job = queue.pull_job()

        assert job is not None
        assert job['id'] == 'job-123'


class TestMessagingConfigIntegration:
    """Tests for MessagingConfig integration."""

    def test_default_config_loaded(self):
        """Test that default config is loaded when not provided."""
        queue = JobQueue()

        assert queue.config is not None
        assert queue.config.push_address is not None
        assert queue.config.pull_address is not None

    def test_config_from_env(self):
        """Test configuration from environment variables."""
        import os
        from src.messaging.config import MessagingConfig

        # Temporarily set env vars
        old_push = os.environ.get('ZMQ_PUSH_ADDRESS')
        old_pull = os.environ.get('ZMQ_PULL_ADDRESS')

        try:
            os.environ['ZMQ_PUSH_ADDRESS'] = 'tcp://192.168.1.1:6666'
            os.environ['ZMQ_PULL_ADDRESS'] = 'tcp://192.168.1.1:6666'

            config = MessagingConfig.from_env()

            assert config.push_address == 'tcp://192.168.1.1:6666'
            assert config.pull_address == 'tcp://192.168.1.1:6666'
        finally:
            # Restore original values
            if old_push is not None:
                os.environ['ZMQ_PUSH_ADDRESS'] = old_push
            else:
                os.environ.pop('ZMQ_PUSH_ADDRESS', None)
            if old_pull is not None:
                os.environ['ZMQ_PULL_ADDRESS'] = old_pull
            else:
                os.environ.pop('ZMQ_PULL_ADDRESS', None)


class TestJobQueueContextManagerErrors:
    """Tests for context manager error handling."""

    def test_context_manager_with_exception(self, mock_config, mock_db_manager):
        """Test context manager properly closes on exception."""
        mock_socket = MagicMock()

        try:
            with JobQueue(config=mock_config, db_manager=mock_db_manager) as queue:
                queue.push_socket = mock_socket
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Socket should still be closed even after exception
        mock_socket.close.assert_called_once()

    def test_exit_returns_false(self, job_queue):
        """Test __exit__ returns False (doesn't suppress exceptions)."""
        result = job_queue.__exit__(ValueError, ValueError("test"), None)

        assert result is False
