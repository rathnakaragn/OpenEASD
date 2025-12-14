"""
Job queue management endpoints.

This module provides API endpoints for monitoring and managing
the persistent job queue used for async scan execution.

Exception handling is centralized in main.py via @app.exception_handler.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query

from src.api.schemas.job import (
    JobResponse,
    JobListResponse,
    JobStatisticsResponse,
    JobStatus,
)
from src.api.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from src.api.dependencies import get_job_service
from src.services.job_service import (
    JobService,
    JobNotFound,
    JobCannotBeRetried,
    JobCannotBeCancelled,
)


router = APIRouter(redirect_slashes=False)


# =============================================================================
# Job Endpoints
# =============================================================================

@router.get("", response_model=JobListResponse)
async def list_jobs(
    status: Optional[JobStatus] = Query(None, description="Filter by job status"),
    job_type: Optional[str] = Query(None, description="Filter by job type (scan, analysis)"),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    service: JobService = Depends(get_job_service)
):
    """
    List jobs with optional filtering.

    Returns a paginated list of jobs with optional status and type filters.
    Jobs are ordered by creation time (most recent first).
    """
    status_value = status.value if status else None

    result = service.list_jobs(
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
    service: JobService = Depends(get_job_service)
):
    """
    Get job queue statistics.

    Returns counts of jobs by status for monitoring the job queue health.
    """
    stats = service.get_statistics()

    return JobStatisticsResponse(**stats)


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    service: JobService = Depends(get_job_service)
):
    """
    Get details of a specific job.

    Returns full job information including payload, timestamps, and error details.
    """
    job = service.get_job(job_id)
    return JobResponse(**job)


@router.post("/{job_id}/retry", response_model=JobResponse)
async def retry_job(
    job_id: str,
    service: JobService = Depends(get_job_service)
):
    """
    Retry a failed job.

    Resets a failed job back to pending status for reprocessing.
    Can only retry jobs that have failed and haven't exceeded max_retries.
    """
    updated_job = service.retry_job(job_id)
    return JobResponse(**updated_job)


@router.post("/{job_id}/cancel", response_model=JobResponse)
async def cancel_job(
    job_id: str,
    service: JobService = Depends(get_job_service)
):
    """
    Cancel a pending or queued job.

    Sets the job status to cancelled. Only jobs in pending or queued status
    can be cancelled. Processing jobs cannot be cancelled via this endpoint.
    """
    updated_job = service.cancel_job(job_id)
    return JobResponse(**updated_job)
