"""
Job SQLModel for persistent job queue.

Jobs are persisted to database before being pushed to ZeroMQ,
ensuring no jobs are lost if workers crash.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, Column, JSON


class Job(SQLModel, table=True):
    """Persistent job model for scan queue."""

    __tablename__ = "jobs"

    id: str = Field(primary_key=True, max_length=255)
    job_type: str = Field(index=True, max_length=50)  # "scan", "analysis", etc.
    payload: Optional[str] = Field(default=None, sa_column=Column(JSON))  # JSON payload

    # Job state
    status: str = Field(default="pending", index=True, max_length=50)
    # Status values: pending, queued, processing, completed, failed, cancelled

    # Relationships
    scan_id: Optional[str] = Field(default=None, index=True, max_length=255)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    queued_at: Optional[datetime] = None  # When pushed to ZeroMQ
    started_at: Optional[datetime] = None  # When worker picked it up
    completed_at: Optional[datetime] = None  # When finished (success or failure)

    # Worker tracking
    worker_id: Optional[str] = Field(default=None, max_length=255)

    # Error handling
    error_message: Optional[str] = Field(default=None, max_length=2000)
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)

    # Priority (lower = higher priority)
    priority: int = Field(default=100, index=True)
