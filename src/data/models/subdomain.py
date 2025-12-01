"""
Subdomain History SQLModel.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class SubdomainHistory(SQLModel, table=True):
    """Subdomain history model for tracking subdomain changes over time."""

    __tablename__ = "subdomain_history"

    id: str = Field(primary_key=True, max_length=255)
    apex_domain: str = Field(
        foreign_key="domains.domain",
        index=True,
        max_length=255
    )  # Index for domain filtering
    subdomain: str = Field(index=True, max_length=255)  # Index for subdomain lookups
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )  # Index for scan-based queries
    status: str = Field(index=True, max_length=50)  # Index for status filtering (new, existing, removed)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow, index=True)  # Index for time-based queries
    tool_source: Optional[str] = Field(default=None, max_length=100)
    meta_data: Optional[str] = Field(default=None, sa_column_kwargs={"name": "metadata"})
