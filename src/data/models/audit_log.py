"""
Audit Log SQLModel for tracking API write operations.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
import uuid


class AuditLog(SQLModel, table=True):
    """Audit log model for tracking all write operations."""

    __tablename__ = "audit_logs"

    id: str = Field(
        primary_key=True,
        default_factory=lambda: str(uuid.uuid4())
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    api_key_id: Optional[str] = Field(default=None, max_length=255)
    endpoint: str = Field(max_length=500)
    method: str = Field(max_length=10)  # GET, POST, PATCH, DELETE
    resource_type: str = Field(max_length=50)  # domain, scan, analysis
    resource_id: Optional[str] = Field(default=None, max_length=255)
    action: str = Field(max_length=50)  # create, update, delete, execute
    ip_address: str = Field(max_length=50)
    user_agent: Optional[str] = Field(default=None, max_length=500)
    request_body: Optional[str] = None  # JSON text
    response_status: int
    success: bool = Field(default=True)
