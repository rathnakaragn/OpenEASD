"""
Data Transfer Objects (DTOs) for internal type hints.

These Pydantic models provide type safety for method return values
in the data layer, complementing the API schemas.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
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


class ScanStatusEnum(str, Enum):
    """Valid scan status values."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanDTO(BaseModel):
    """
    Data Transfer Object for Scan session data.

    Used for type-safe returns from scan-related methods.
    """
    scan_id: str = Field(..., description="Scan UUID")
    scan_type: str = Field(..., description="Type of scan")
    tool_name: Optional[str] = Field(None, description="Tool name")
    domains_scanned: List[str] = Field(default_factory=list, description="Domains")
    start_time: Optional[datetime] = Field(None, description="Start time")
    end_time: Optional[datetime] = Field(None, description="End time")
    status: str = Field(default="running", description="Scan status")
    findings_count: int = Field(default=0, description="Number of findings")


class FindingSeverityEnum(str, Enum):
    """Valid finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatusEnum(str, Enum):
    """Valid finding status values."""
    NEW = "new"
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


class FindingDTO(BaseModel):
    """
    Data Transfer Object for Finding data.

    Used for type-safe returns from finding-related methods.
    """
    id: str = Field(..., description="Finding UUID")
    scan_id: str = Field(..., description="Associated scan ID")
    finding_type: str = Field(..., description="Type of finding")
    affected_asset: str = Field(..., description="Affected domain/host")
    port: Optional[int] = Field(None, description="Port number")
    protocol: Optional[str] = Field(None, description="Protocol (tcp/udp)")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = Field(None, description="Description")
    severity: str = Field(default="medium", description="Severity level")
    risk_score: int = Field(default=50, description="Risk score 0-100")
    status: str = Field(default="new", description="Finding status")
    detector: Optional[str] = Field(None, description="Detector name")
    evidence_json: Optional[Dict[str, Any]] = Field(None, description="Evidence")
    first_seen: Optional[datetime] = Field(None, description="First seen")
    last_seen: Optional[datetime] = Field(None, description="Last seen")


class DomainDTO(BaseModel):
    """
    Data Transfer Object for Domain data.

    Used for type-safe returns from domain-related methods.
    """
    domain: str = Field(..., description="Domain name (primary key)")
    is_primary: bool = Field(default=False, description="Primary domain flag")
    contact_email: Optional[str] = Field(None, description="Contact email")
    scan_frequency: Optional[str] = Field(None, description="Scan frequency")
    active_scan_enabled: bool = Field(default=True, description="Active scan flag")
    scan_count: int = Field(default=0, description="Number of scans")
    created_at: Optional[datetime] = Field(None, description="Creation time")
    updated_at: Optional[datetime] = Field(None, description="Last update time")
    last_scanned_at: Optional[datetime] = Field(None, description="Last scan time")


class PaginatedResponse(BaseModel):
    """
    Generic paginated response structure.

    Base model for list responses with pagination.
    """
    total_count: int = Field(..., description="Total items")
    has_more: bool = Field(..., description="More items available")
    limit: int = Field(..., description="Items per page")
    offset: int = Field(..., description="Current offset")


class JobListDTO(PaginatedResponse):
    """Paginated job list response."""
    jobs: List[JobDTO] = Field(default_factory=list)


class FindingListDTO(PaginatedResponse):
    """Paginated finding list response."""
    findings: List[FindingDTO] = Field(default_factory=list)


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
