"""
ZeroMQ Job Queue - PUSH/PULL Pattern with Database Persistence.

Jobs are saved to database FIRST, then pushed to ZeroMQ queue.
This ensures no jobs are lost if workers crash.

Recovery mechanisms:
1. Stale job recovery: Jobs stuck in 'processing' for too long are recovered
2. Pending job recovery: Jobs that failed to queue can be retried
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, TYPE_CHECKING

import zmq

from src.messaging.config import get_messaging_config, MessagingConfig

if TYPE_CHECKING:
    from src.data.database.sqlmodel_manager import SQLModelManager

logger = logging.getLogger(__name__)


class JobQueue:
    """
    ZeroMQ-based job queue with database persistence.

    Jobs are persisted to SQLite before being pushed to ZeroMQ.
    If a worker crashes, the job can be recovered from the database.

    Usage (Producer - API side):
        queue = JobQueue(db_manager=db_manager)
        queue.connect_push()
        job_id = queue.push_job("scan", {"domain_id": "123"})

    Usage (Consumer - Worker side):
        queue = JobQueue(db_manager=db_manager)
        queue.connect_pull()
        job = queue.pull_job()
        # Process job...
        queue.complete_job(job['id'], success=True)
    """

    def __init__(
        self,
        config: MessagingConfig = None,
        db_manager: "SQLModelManager" = None
    ):
        """
        Initialize job queue.

        Args:
            config: Messaging configuration (uses default if not provided)
            db_manager: Database manager for job persistence (optional but recommended)
        """
        self.config = config or get_messaging_config()
        self.context = zmq.Context.instance()
        self.push_socket: Optional[zmq.Socket] = None
        self.pull_socket: Optional[zmq.Socket] = None
        self.db_manager = db_manager
        self._worker_id: Optional[str] = None

    def set_db_manager(self, db_manager: "SQLModelManager") -> None:
        """
        Set database manager for job persistence.

        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager

    def set_worker_id(self, worker_id: str) -> None:
        """
        Set worker ID for job claiming.

        Args:
            worker_id: Unique worker identifier
        """
        self._worker_id = worker_id

    def connect_push(self) -> None:
        """Connect PUSH socket (for producers/API)."""
        if self.push_socket is not None:
            return

        self.push_socket = self.context.socket(zmq.PUSH)
        self.push_socket.setsockopt(zmq.SNDTIMEO, self.config.send_timeout)
        self.push_socket.setsockopt(zmq.SNDHWM, self.config.high_water_mark)
        self.push_socket.connect(self.config.push_address)
        logger.info(f"PUSH socket connected to {self.config.push_address}")

    def connect_pull(self) -> None:
        """Bind PULL socket (for consumers/workers)."""
        if self.pull_socket is not None:
            return

        self.pull_socket = self.context.socket(zmq.PULL)
        self.pull_socket.setsockopt(zmq.RCVTIMEO, self.config.recv_timeout)
        self.pull_socket.setsockopt(zmq.RCVHWM, self.config.high_water_mark)
        self.pull_socket.bind(self.config.pull_address)
        logger.info(f"PULL socket bound to {self.config.pull_address}")

    def push_job(
        self,
        job_type: str,
        payload: Dict[str, Any],
        scan_id: Optional[str] = None,
        priority: int = 100
    ) -> str:
        """
        Push a job to the queue with database persistence.

        The job is saved to the database FIRST, then pushed to ZeroMQ.
        This ensures the job can be recovered if the worker crashes.

        Args:
            job_type: Type of job (e.g., "scan", "analysis")
            payload: Job data
            scan_id: Optional associated scan ID
            priority: Job priority (lower = higher priority)

        Returns:
            Job ID

        Raises:
            RuntimeError: If PUSH socket not connected
            zmq.Again: If queue is full (timeout)
        """
        if self.push_socket is None:
            raise RuntimeError("PUSH socket not connected. Call connect_push() first.")

        job_id = str(uuid.uuid4())

        # Step 1: Persist job to database (if db_manager available)
        if self.db_manager:
            try:
                self.db_manager.create_job(
                    job_id=job_id,
                    job_type=job_type,
                    payload=payload,
                    scan_id=scan_id,
                    priority=priority
                )
                logger.debug(f"Job {job_id} persisted to database")
            except Exception as e:
                logger.error(f"Failed to persist job {job_id} to database: {e}")
                raise

        # Step 2: Build job message for ZeroMQ
        job = {
            "id": job_id,
            "type": job_type,
            "payload": payload,
            "submitted_at": datetime.utcnow().isoformat(),
        }

        # Step 3: Push to ZeroMQ
        try:
            self.push_socket.send_json(job)
            logger.info(f"Pushed job {job_id} (type: {job_type})")

            # Step 4: Mark job as queued in database
            if self.db_manager:
                try:
                    self.db_manager.mark_job_queued(job_id)
                except Exception as e:
                    # Non-critical: job is already in queue, just log warning
                    logger.warning(f"Failed to mark job {job_id} as queued: {e}")

            return job_id

        except zmq.Again:
            logger.error(f"Failed to push job {job_id}: queue full or timeout")
            # Job remains in 'pending' status in database for later recovery
            raise

    def pull_job(self, block: bool = True) -> Optional[Dict[str, Any]]:
        """
        Pull a job from the queue.

        Args:
            block: If True, block until job available (with timeout)

        Returns:
            Job dictionary or None if no job available

        Raises:
            RuntimeError: If PULL socket not connected
        """
        if self.pull_socket is None:
            raise RuntimeError("PULL socket not connected. Call connect_pull() first.")

        try:
            message = self.pull_socket.recv_json(flags=0 if block else zmq.NOBLOCK)
            job_id = message.get('id')
            logger.info(f"Pulled job {job_id} (type: {message.get('type')})")

            # Claim job in database (if db_manager available)
            if self.db_manager and job_id:
                worker_id = self._worker_id or f"worker-{uuid.uuid4().hex[:8]}"
                try:
                    claimed = self.db_manager.claim_job(job_id, worker_id)
                    if not claimed:
                        # Job already claimed by another worker - don't process it
                        logger.warning(f"Job {job_id} already claimed by another worker, skipping")
                        return None
                except Exception as e:
                    # Claim failed - don't process to avoid duplicate execution
                    logger.error(f"Failed to claim job {job_id}: {e}, skipping")
                    return None

            return message

        except zmq.Again:
            # Timeout or no message available
            return None

    def complete_job(
        self,
        job_id: str,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark a job as completed or failed in the database.

        Args:
            job_id: Job ID to complete
            success: True for completed, False for failed
            error_message: Error message if failed

        Returns:
            True if updated, False if db_manager not available or job not found
        """
        if not self.db_manager:
            logger.debug(f"No db_manager, skipping job completion for {job_id}")
            return False

        try:
            return self.db_manager.complete_job(job_id, success, error_message)
        except Exception as e:
            logger.error(f"Failed to complete job {job_id}: {e}")
            return False

    def close(self) -> None:
        """Close all sockets."""
        if self.push_socket is not None:
            self.push_socket.close()
            self.push_socket = None
            logger.info("PUSH socket closed")

        if self.pull_socket is not None:
            self.pull_socket.close()
            self.pull_socket = None
            logger.info("PULL socket closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


# Singleton instance for API usage
_job_queue: Optional[JobQueue] = None


def get_job_queue(db_manager: "SQLModelManager" = None) -> JobQueue:
    """
    Get job queue singleton (for API dependency injection).

    Args:
        db_manager: Optional database manager for job persistence

    Returns:
        JobQueue singleton instance
    """
    global _job_queue
    if _job_queue is None:
        _job_queue = JobQueue(db_manager=db_manager)
        _job_queue.connect_push()
    elif db_manager and _job_queue.db_manager is None:
        _job_queue.set_db_manager(db_manager)
    return _job_queue
