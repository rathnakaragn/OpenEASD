"""
Domain SQLModel.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, Column, JSON


class Domain(SQLModel, table=True):
    """Domain model for tracking monitored domains."""

    __tablename__ = "domains"

    domain: str = Field(primary_key=True, max_length=255)
    domain_type: str = Field(default="apex", max_length=50)
    is_primary: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_scanned_at: Optional[datetime] = None
    scan_count: int = Field(default=0)
    notes: Optional[str] = None
    tags: Optional[str] = Field(default=None, sa_column=Column(JSON))  # JSON array
    contact_email: Optional[str] = Field(default=None, max_length=255)
    scan_frequency: Optional[str] = Field(default=None, max_length=50)
    active_scan_enabled: bool = Field(default=True)
