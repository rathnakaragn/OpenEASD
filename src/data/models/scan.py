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
    scan_type: str = Field(max_length=100)
    tool_name: Optional[str] = Field(default=None, max_length=100)
    domains_scanned: Optional[str] = Field(default=None, sa_column=Column(JSON))  # JSON array
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    status: str = Field(default="queued", max_length=50)
    findings_count: int = Field(default=0)
