"""
Common Pydantic schemas used across the API.
"""

import re
from enum import Enum
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field


# =============================================================================
# Pagination Constants
# =============================================================================

DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100


# =============================================================================
# Enums for consistent validation across the API
# =============================================================================

class ScanStatus(str, Enum):
    """Valid scan statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(str, Enum):
    """Valid finding statuses."""
    NEW = "new"
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


class Severity(str, Enum):
    """Valid severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanFrequency(str, Enum):
    """Valid scan frequency options."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# =============================================================================
# Shared validators
# =============================================================================

def validate_domain_format(domain: str) -> str:
    """
    Validate domain format and normalize to lowercase.

    Args:
        domain: Domain string to validate

    Returns:
        Normalized domain string

    Raises:
        ValueError: If domain format is invalid
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError('Domain cannot be empty')
    # Basic domain pattern: allows subdomains and TLDs
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        raise ValueError(f'Invalid domain format: {domain}')
    return domain


# =============================================================================
# Response schemas
# =============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    database: str


class ErrorResponse(BaseModel):
    """Standardized error response format matching exception handlers."""
    detail: str = Field(..., description="Human-readable error message")
    error_code: str = Field(..., description="Machine-readable error code")


class MessageResponse(BaseModel):
    """Simple message response."""
    message: str
    success: bool = True
    details: Optional[Dict[str, Any]] = None
