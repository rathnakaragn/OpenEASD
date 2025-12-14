"""
Job queue management endpoints.

This module provides API endpoints for monitoring and managing
the persistent job queue used for async scan execution.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from typing import Optional, Any
from fastapi import APIRouter, Depends, Query, status

from src.api.schemas.job import (
    JobResponse,
    JobListResponse,
    JobStatisticsResponse,
    JobStatus,
)
from src.api.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from src.api.dependencies import get_db_manager


router = APIRouter(redirect_slashes=False)


# =============================================================================
# Custom Exceptions for Jobs
# =============================================================================

class JobNotFound(Exception):
    """Raised when a job is not found."""
    pass


class JobCannotBeRetried(Exception):
    """Raised when a job cannot be retried."""
    pass


class JobCannotBeCancelled(Exception):
    """Raised when a job cannot be cancelled."""
    pass


# =============================================================================
# Job Endpoints
# =============================================================================

@router.get("", response_model=JobListResponse)
async def list_jobs(
    status: Optional[JobStatus] = Query(None, description="Filter by job status"),
    job_type: Optional[str] = Query(None, description="Filter by job type (scan, analysis)"),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Any = Depends(get_db_manager)
):
    """
    List jobs with optional filtering.

    Returns a paginated list of jobs with optional status and type filters.
    Jobs are ordered by creation time (most recent first).
    """
    # Convert enum to string value if provided
    status_value = status.value if status else None

    result = db.list_jobs(
        status=status_value,
        job_type=job_type,
        limit=limit,
        offset=offset
    )

    return JobListResponse(
        jobs=result['jobs'],
        total_count=result['total'],
        limit=result['limit'],
        offset=result['offset'],
        has_more=result['has_more']
    )


@router.get("/statistics", response_model=JobStatisticsResponse)
async def get_job_statistics(
    db: Any = Depends(get_db_manager)
):
    """
    Get job queue statistics.

    Returns counts of jobs by status for monitoring the job queue health.
    """
    stats = db.get_job_statistics()

    return JobStatisticsResponse(
        pending=stats.get('pending', 0),
        queued=stats.get('queued', 0),
        processing=stats.get('processing', 0),
        completed=stats.get('completed', 0),
        failed=stats.get('failed', 0),
        cancelled=stats.get('cancelled', 0),
        total=stats.get('total', 0)
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    db: Any = Depends(get_db_manager)
):
    """
    Get details of a specific job.

    Returns full job information including payload, timestamps, and error details.
    """
    job = db.get_job(job_id)

    if not job:
        raise JobNotFound(f"Job {job_id} not found")

    return JobResponse(**job)


@router.post("/{job_id}/retry", response_model=JobResponse)
async def retry_job(
    job_id: str,
    db: Any = Depends(get_db_manager)
):
    """
    Retry a failed job.

    Resets a failed job back to pending status for reprocessing.
    Can only retry jobs that have failed and haven't exceeded max_retries.
    """
    # First check if job exists and get its current state
    job = db.get_job(job_id)

    if not job:
        raise JobNotFound(f"Job {job_id} not found")

    # Check if job can be retried
    if job['status'] != 'failed':
        raise JobCannotBeRetried(
            f"Cannot retry job {job_id}: job status is '{job['status']}', "
            "only failed jobs can be retried"
        )

    if job['retry_count'] >= job['max_retries']:
        raise JobCannotBeRetried(
            f"Cannot retry job {job_id}: max retries ({job['max_retries']}) exceeded"
        )

    # Perform the retry
    success = db.retry_job(job_id)

    if not success:
        raise JobCannotBeRetried(f"Failed to retry job {job_id}")

    # Return updated job
    updated_job = db.get_job(job_id)
    return JobResponse(**updated_job)


@router.post("/{job_id}/cancel", response_model=JobResponse)
async def cancel_job(
    job_id: str,
    db: Any = Depends(get_db_manager)
):
    """
    Cancel a pending or queued job.

    Sets the job status to cancelled. Only jobs in pending or queued status
    can be cancelled. Processing jobs cannot be cancelled via this endpoint.
    """
    # First check if job exists and get its current state
    job = db.get_job(job_id)

    if not job:
        raise JobNotFound(f"Job {job_id} not found")

    # Check if job can be cancelled
    if job['status'] not in ('pending', 'queued'):
        raise JobCannotBeCancelled(
            f"Cannot cancel job {job_id}: job status is '{job['status']}', "
            "only pending or queued jobs can be cancelled"
        )

    # Perform the cancellation
    success = db.cancel_job(job_id)

    if not success:
        raise JobCannotBeCancelled(f"Failed to cancel job {job_id}")

    # Return updated job
    updated_job = db.get_job(job_id)
    return JobResponse(**updated_job)
