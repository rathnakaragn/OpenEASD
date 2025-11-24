"""
Common Pydantic schemas used across the API.
"""

from pydantic import BaseModel
from typing import Optional


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    database: str


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class MessageResponse(BaseModel):
    """Simple message response."""
    message: str
    success: bool = True
