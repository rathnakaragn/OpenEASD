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
    apex_domain: str = Field(max_length=255)
    subdomain: str = Field(max_length=255)
    scan_id: str = Field(max_length=255)
    status: str = Field(max_length=50)  # new, existing, removed
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tool_source: Optional[str] = Field(default=None, max_length=100)
    meta_data: Optional[str] = Field(default=None, sa_column_kwargs={"name": "metadata"})
