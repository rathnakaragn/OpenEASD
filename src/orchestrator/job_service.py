"""
Job management service.

Handles business logic for job queue operations.
"""

import logging
from typing import Dict, Any, Optional, List

from src.data.database.sqlmodel_manager import SQLModelManager


logger = logging.getLogger(__name__)


class JobNotFound(Exception):
    """Raised when a job is not found."""
    pass


class JobCannotBeRetried(Exception):
    """Raised when a job cannot be retried."""
    pass


class JobCannotBeCancelled(Exception):
    """Raised when a job cannot be cancelled."""
    pass


class JobService:
    """Service for managing jobs (business logic layer)."""

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize job service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

    def list_jobs(
        self,
        status: Optional[str] = None,
        job_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        List jobs with optional filtering.

        Args:
            status: Filter by job status
            job_type: Filter by job type (scan, analysis)
            limit: Maximum results per page
            offset: Offset for pagination

        Returns:
            Dictionary containing jobs list and pagination info
        """
        result = self.db.list_jobs(
            status=status,
            job_type=job_type,
            limit=limit,
            offset=offset
        )

        return {
            'jobs': result['jobs'],
            'total': result['total'],
            'limit': result['limit'],
            'offset': result['offset'],
            'has_more': result['has_more']
        }

    def get_job(self, job_id: str) -> Dict[str, Any]:
        """
        Get details of a specific job.

        Args:
            job_id: Job ID

        Returns:
            Job information dictionary

        Raises:
            JobNotFound: If job doesn't exist
        """
        job = self.db.get_job(job_id)

        if not job:
            raise JobNotFound(f"Job {job_id} not found")

        return job

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get job queue statistics.

        Returns:
            Dictionary with counts by status
        """
        stats = self.db.get_job_statistics()

        return {
            'pending': stats.get('pending', 0),
            'queued': stats.get('queued', 0),
            'processing': stats.get('processing', 0),
            'completed': stats.get('completed', 0),
            'failed': stats.get('failed', 0),
            'cancelled': stats.get('cancelled', 0),
            'total': stats.get('total', 0)
        }

    def retry_job(self, job_id: str) -> Dict[str, Any]:
        """
        Retry a failed job.

        Args:
            job_id: Job ID to retry

        Returns:
            Updated job information

        Raises:
            JobNotFound: If job doesn't exist
            JobCannotBeRetried: If job cannot be retried
        """
        job = self.db.get_job(job_id)

        if not job:
            raise JobNotFound(f"Job {job_id} not found")

        if job['status'] != 'failed':
            raise JobCannotBeRetried(
                f"Cannot retry job {job_id}: job status is '{job['status']}', "
                "only failed jobs can be retried"
            )

        if job['retry_count'] >= job['max_retries']:
            raise JobCannotBeRetried(
                f"Cannot retry job {job_id}: max retries ({job['max_retries']}) exceeded"
            )

        success = self.db.retry_job(job_id)

        if not success:
            raise JobCannotBeRetried(f"Failed to retry job {job_id}")

        logger.info(f"Retried job {job_id}")

        return self.db.get_job(job_id)

    def cancel_job(self, job_id: str) -> Dict[str, Any]:
        """
        Cancel a pending or queued job.

        Args:
            job_id: Job ID to cancel

        Returns:
            Updated job information

        Raises:
            JobNotFound: If job doesn't exist
            JobCannotBeCancelled: If job cannot be cancelled
        """
        job = self.db.get_job(job_id)

        if not job:
            raise JobNotFound(f"Job {job_id} not found")

        if job['status'] not in ('pending', 'queued'):
            raise JobCannotBeCancelled(
                f"Cannot cancel job {job_id}: job status is '{job['status']}', "
                "only pending or queued jobs can be cancelled"
            )

        success = self.db.cancel_job(job_id)

        if not success:
            raise JobCannotBeCancelled(f"Failed to cancel job {job_id}")

        logger.info(f"Cancelled job {job_id}")

        return self.db.get_job(job_id)
