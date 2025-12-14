#!/usr/bin/env python3
"""
Scan Worker - Processes scan jobs from ZeroMQ queue.

Run with: python -m workers.scan_worker

Features:
- Database-persisted jobs (survives worker crashes)
- Stale job recovery (detects stuck jobs)
- Graceful shutdown handling
- Job completion tracking

Workflow:
1. Pull job from queue
2. Claim job in database
3. Update scan status to "running"
4. Execute tools (subfinder, naabu, etc.)
5. Run analysis (risk scoring)
6. Save results to database
7. Update scan status to "completed"
8. Mark job as completed
"""

import logging
import signal
import sys
import time
import uuid
from typing import Dict, Any, Optional

# Add project root to path
sys.path.insert(0, str(__file__).rsplit("/workers", 1)[0])

from src.messaging.job_queue import JobQueue
from src.services.scan_service import ScanService
from src.data.database.sqlmodel_manager import SQLModelManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Stale job threshold (minutes)
STALE_JOB_THRESHOLD_MINUTES = 30

# Recovery check interval (seconds)
RECOVERY_CHECK_INTERVAL = 60


class ScanWorker:
    """Worker that processes scan jobs with database persistence."""

    def __init__(self):
        """Initialize worker with dependencies."""
        self.running = False
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"

        # Initialize database first
        self.db_manager = SQLModelManager()
        self.db_manager.initialize()

        # Initialize job queue with database manager
        self.job_queue = JobQueue(db_manager=self.db_manager)
        self.job_queue.set_worker_id(self.worker_id)

        # Initialize scan service
        self.scan_service = ScanService(db_manager=self.db_manager)

        # Last recovery check timestamp
        self._last_recovery_check = 0

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        logger.info(f"Worker initialized with ID: {self.worker_id}")

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def start(self):
        """Start processing jobs."""
        logger.info("Scan worker starting...")
        self.job_queue.connect_pull()
        self.running = True

        # Recover any stale jobs on startup
        self._recover_stale_jobs()

        logger.info("Waiting for jobs...")
        while self.running:
            try:
                # Periodically check for stale jobs
                self._periodic_recovery_check()

                job = self.job_queue.pull_job(block=True)
                if job:
                    self._process_job(job)

            except Exception as e:
                logger.error(f"Error pulling job: {e}", exc_info=True)
                time.sleep(1)  # Avoid tight loop on errors

        self._cleanup()

    def _periodic_recovery_check(self):
        """Periodically check for stale jobs that need recovery."""
        current_time = time.time()
        if current_time - self._last_recovery_check > RECOVERY_CHECK_INTERVAL:
            self._recover_stale_jobs()
            self._last_recovery_check = current_time

    def _recover_stale_jobs(self):
        """
        Recover stale jobs that have been processing for too long.

        Stale jobs are likely from crashed workers and need to be
        reset for retry.
        """
        try:
            stale_jobs = self.db_manager.get_stale_jobs(
                stale_minutes=STALE_JOB_THRESHOLD_MINUTES
            )

            if not stale_jobs:
                return

            logger.warning(f"Found {len(stale_jobs)} stale jobs, recovering...")

            for job in stale_jobs:
                job_id = job['id']
                scan_id = job.get('scan_id')

                # Mark the associated scan as failed
                if scan_id:
                    try:
                        self.scan_service.update_scan_status(
                            scan_id, "failed",
                            error="Job timed out (worker may have crashed)"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to update scan {scan_id} status: {e}")

                # Try to retry the job
                if self.db_manager.retry_job(job_id):
                    logger.info(f"Job {job_id} reset for retry (attempt {job['retry_count'] + 1})")
                else:
                    # Max retries exceeded, mark as failed
                    self.db_manager.complete_job(
                        job_id,
                        success=False,
                        error_message="Max retries exceeded after worker crashes"
                    )
                    logger.error(f"Job {job_id} failed permanently after max retries")

        except Exception as e:
            logger.error(f"Error recovering stale jobs: {e}", exc_info=True)

    def _process_job(self, job: Dict[str, Any]):
        """
        Process a single job.

        Args:
            job: Job dictionary with id, type, payload
        """
        job_id = job.get("id", "unknown")
        job_type = job.get("type", "unknown")
        payload = job.get("payload", {})

        logger.info(f"Processing job {job_id} (type: {job_type})")

        try:
            if job_type == "scan":
                self._process_scan_job(job_id, payload)
            else:
                logger.warning(f"Unknown job type: {job_type}")
                self.job_queue.complete_job(job_id, success=False, error_message=f"Unknown job type: {job_type}")

        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}", exc_info=True)
            self._handle_job_failure(job_id, payload, str(e))

    def _process_scan_job(self, job_id: str, payload: Dict[str, Any]):
        """
        Process a scan job.

        Args:
            job_id: Job ID from the queue
            payload: Scan job payload with scan_id, domain, and timeout
        """
        scan_id = payload.get("scan_id")
        domain = payload.get("domain")
        timeout = payload.get("timeout")

        if not scan_id or not domain:
            error_msg = f"Invalid scan payload: missing scan_id or domain"
            logger.error(error_msg)
            self.job_queue.complete_job(job_id, success=False, error_message=error_msg)
            return

        logger.info(f"Starting scan {scan_id} for domain {domain} (timeout: {timeout}s)")

        try:
            # Update scan status to running
            try:
                self.scan_service.update_scan_status(scan_id, "running")
            except Exception as e:
                logger.error(f"Failed to update scan status to running: {e}")
                raise  # Cannot proceed without status update

            # Execute the scan workflow
            result = self.scan_service.execute_scan_workflow(scan_id, domain, timeout=timeout)

            # Update scan status to completed
            try:
                self.scan_service.update_scan_status(scan_id, "completed")
            except Exception as e:
                logger.error(f"Failed to update scan status to completed: {e}")
                # Scan succeeded but status update failed
                try:
                    self.scan_service.update_scan_status(
                        scan_id, "failed",
                        error=f"Scan completed but status update failed: {e}"
                    )
                except Exception:
                    pass

            # Update domain scan count
            try:
                self.db_manager.increment_domain_scan_count(domain)
                logger.info(f"Updated scan count for domain {domain}")
            except Exception as e:
                # Non-critical: log warning but don't fail the scan
                logger.warning(f"Failed to update domain scan count: {e}")

            # Mark job as completed
            self.job_queue.complete_job(job_id, success=True)
            logger.info(f"Scan {scan_id} completed successfully: {result}")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)

            # Update scan status to failed
            try:
                self.scan_service.update_scan_status(scan_id, "failed", error=str(e))
            except Exception as status_err:
                logger.error(f"Failed to update scan status to failed: {status_err}")

            # Mark job as failed (with potential retry)
            self.job_queue.complete_job(job_id, success=False, error_message=str(e))
            raise

    def _handle_job_failure(self, job_id: str, payload: Dict[str, Any], error: str):
        """Handle job failure by updating scan and job status."""
        scan_id = payload.get("scan_id")

        # Update scan status
        if scan_id:
            try:
                self.scan_service.update_scan_status(scan_id, "failed", error=error)
            except Exception as e:
                logger.error(f"Failed to update scan status: {e}")

        # Mark job as failed
        self.job_queue.complete_job(job_id, success=False, error_message=error)

    def _cleanup(self):
        """Cleanup resources."""
        logger.info("Cleaning up...")
        self.job_queue.close()
        self.db_manager.close()
        logger.info("Worker stopped")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get worker and job queue statistics.

        Returns:
            Dictionary with statistics
        """
        job_stats = self.db_manager.get_job_statistics()
        return {
            'worker_id': self.worker_id,
            'running': self.running,
            'job_stats': job_stats
        }


def main():
    """Entry point for scan worker."""
    logger.info("=" * 50)
    logger.info("OpenEASD Scan Worker")
    logger.info("=" * 50)
    logger.info("Features:")
    logger.info("  - Database-persisted jobs")
    logger.info("  - Stale job recovery")
    logger.info("  - Graceful shutdown (Ctrl+C)")
    logger.info("=" * 50)

    worker = ScanWorker()
    worker.start()


if __name__ == "__main__":
    main()
