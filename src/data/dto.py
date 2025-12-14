"""
Data Transfer Objects (DTOs) for internal type hints.

These Pydantic models provide type safety for method return values
in the data layer, complementing the API schemas.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class JobStatusEnum(str, Enum):
    """Valid job status values."""
    PENDING = "pending"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobDTO(BaseModel):
    """
    Data Transfer Object for Job data.

    Used for type-safe returns from database methods like:
    - get_job()
    - get_stale_jobs()
    - get_pending_jobs()
    - list_jobs()
    """
    id: str = Field(..., description="Job UUID")
    job_type: str = Field(..., description="Type of job (scan, analysis)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Job payload")
    status: str = Field(..., description="Job status")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    created_at: Optional[str] = Field(None, description="Creation timestamp ISO")
    queued_at: Optional[str] = Field(None, description="Queue timestamp ISO")
    started_at: Optional[str] = Field(None, description="Start timestamp ISO")
    completed_at: Optional[str] = Field(None, description="Completion timestamp ISO")
    worker_id: Optional[str] = Field(None, description="Worker ID")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    retry_count: int = Field(default=0, description="Retry attempts")
    max_retries: int = Field(default=3, description="Maximum retries")
    priority: int = Field(default=100, description="Job priority")


class JobStatisticsDTO(BaseModel):
    """Job queue statistics."""
    pending: int = Field(default=0)
    queued: int = Field(default=0)
    processing: int = Field(default=0)
    completed: int = Field(default=0)
    failed: int = Field(default=0)
    cancelled: int = Field(default=0)
    total: int = Field(default=0)


class FindingStatisticsDTO(BaseModel):
    """Finding statistics."""
    total_findings: int = Field(default=0)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    average_risk_score: float = Field(default=0.0)
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)
    medium_findings: int = Field(default=0)
    low_findings: int = Field(default=0)
    info_findings: int = Field(default=0)
    active_findings: int = Field(default=0)
    closed_findings: int = Field(default=0)
