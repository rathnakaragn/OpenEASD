"""
Security Alert SQLModel.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class SecurityAlert(SQLModel, table=True):
    """Security alert model for tracking discovered vulnerabilities."""

    __tablename__ = "security_alerts"

    id: str = Field(primary_key=True, max_length=255)
    domain: str = Field(max_length=255)
    scan_id: Optional[str] = Field(default=None, max_length=255)
    vulnerability_type: str = Field(max_length=100)
    severity: str = Field(max_length=50)
    description: Optional[str] = None
    remediation: Optional[str] = None
    tool_source: Optional[str] = Field(default=None, max_length=100)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
