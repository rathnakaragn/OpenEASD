"""
Pydantic schemas for job queue API endpoints.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class JobStatus(str, Enum):
    """Valid job statuses."""
    PENDING = "pending"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobResponse(BaseModel):
    """Response schema for a single job."""
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "job_type": "scan",
                "payload": {"scan_id": "abc123", "domain": "example.com"},
                "status": "processing",
                "scan_id": "abc123",
                "worker_id": "worker-001",
                "created_at": "2025-12-04T10:00:00Z",
                "queued_at": "2025-12-04T10:00:01Z",
                "started_at": "2025-12-04T10:01:00Z",
                "completed_at": None,
                "error_message": None,
                "retry_count": 0,
                "max_retries": 3,
                "priority": 100
            }
        }
    )

    id: str = Field(..., description="Job UUID")
    job_type: str = Field(..., description="Type of job (scan, analysis, etc.)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Job payload data")
    status: JobStatus = Field(..., description="Job status")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    worker_id: Optional[str] = Field(None, description="Worker processing this job")
    created_at: Optional[datetime] = Field(None, description="When job was created")
    queued_at: Optional[datetime] = Field(None, description="When job was pushed to queue")
    started_at: Optional[datetime] = Field(None, description="When worker started processing")
    completed_at: Optional[datetime] = Field(None, description="When job finished")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    max_retries: int = Field(default=3, description="Maximum retry attempts allowed")
    priority: int = Field(default=100, description="Job priority (lower = higher priority)")


class JobListResponse(BaseModel):
    """Response schema for list of jobs."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "jobs": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "job_type": "scan",
                    "status": "processing",
                    "scan_id": "abc123",
                    "created_at": "2025-12-04T10:00:00Z"
                }
            ],
            "total_count": 50,
            "limit": 20,
            "offset": 0,
            "has_more": True
        }
    })

    jobs: List[JobResponse] = Field(..., description="List of jobs")
    total_count: int = Field(..., description="Total number of jobs")
    limit: int = Field(..., description="Results per page")
    offset: int = Field(..., description="Current offset")
    has_more: bool = Field(..., description="More results available")


class JobStatisticsResponse(BaseModel):
    """Response schema for job statistics."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "pending": 5,
            "queued": 3,
            "processing": 2,
            "completed": 100,
            "failed": 1,
            "cancelled": 0,
            "total": 111
        }
    })

    pending: int = Field(..., description="Jobs waiting to be queued")
    queued: int = Field(..., description="Jobs in ZeroMQ queue")
    processing: int = Field(..., description="Jobs being processed by workers")
    completed: int = Field(..., description="Successfully completed jobs")
    failed: int = Field(..., description="Failed jobs")
    cancelled: int = Field(..., description="Cancelled jobs")
    total: int = Field(..., description="Total number of jobs")
