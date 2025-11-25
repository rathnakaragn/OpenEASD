"""
Domain SQLModel.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class Domain(SQLModel, table=True):
    """Domain model for tracking monitored domains."""

    __tablename__ = "domains"

    domain: str = Field(primary_key=True, max_length=255)
    is_primary: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_scanned_at: Optional[datetime] = None
    scan_count: int = Field(default=0)
    contact_email: Optional[str] = Field(default=None, max_length=255)
    scan_frequency: Optional[str] = Field(default=None, max_length=50)
    active_scan_enabled: bool = Field(default=True)
