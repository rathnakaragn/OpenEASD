"""
API Key SQLModel for authentication and authorization.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
import uuid


class APIKey(SQLModel, table=True):
    """API Key model for API authentication."""

    __tablename__ = "api_keys"

    id: str = Field(
        primary_key=True,
        default_factory=lambda: str(uuid.uuid4())
    )
    key: str = Field(unique=True, index=True, max_length=255)  # SHA-256 hashed
    name: str = Field(max_length=255)  # Human-readable name
    permissions: str = Field(default="[]", max_length=1000)  # JSON array: ["domain:write", "scan:execute"]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool = Field(default=True)
