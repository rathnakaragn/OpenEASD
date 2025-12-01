"""
Scan Session SQLModel.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, Column, JSON


class ScanSession(SQLModel, table=True):
    """Scan session model for tracking security scans."""

    __tablename__ = "scan_sessions"

    scan_id: str = Field(primary_key=True, max_length=255)
    scan_type: str = Field(index=True, max_length=100)  # Index for filtering by type
    tool_name: Optional[str] = Field(default=None, index=True, max_length=100)  # Index for tool queries
    domains_scanned: Optional[str] = Field(default=None, sa_column=Column(JSON))  # JSON array
    start_time: datetime = Field(default_factory=datetime.utcnow, index=True)  # Index for time-based queries
    end_time: Optional[datetime] = None
    status: str = Field(default="queued", index=True, max_length=50)  # Index for status filtering
    findings_count: int = Field(default=0)
