"""
Timezone utilities for OpenEASD API.

Handles conversion of datetime objects to IST (Indian Standard Time)
and formatting with 24-hour format.
"""

import pytz
from datetime import datetime
from typing import Optional, Union


# IST timezone constant
IST = pytz.timezone('Asia/Kolkata')


def get_ist_now() -> datetime:
    """Get current datetime in IST timezone."""
    return datetime.now(IST)


def to_ist(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Convert datetime to IST timezone.
    
    Args:
        dt: Datetime object (can be naive or timezone-aware)
        
    Returns:
        Datetime object in IST timezone, or None if input is None
    """
    if dt is None:
        return None
    
    # If datetime is naive (no timezone), assume it's UTC
    if dt.tzinfo is None:
        dt = pytz.UTC.localize(dt)
    
    # Convert to IST
    return dt.astimezone(IST)


def format_datetime_iso(dt: Optional[Union[datetime, str]]) -> str:
    """
    Format datetime to ISO format string.

    Handles both datetime objects and strings gracefully.
    Used for API responses and data serialization.

    Args:
        dt: Datetime object or string to format

    Returns:
        ISO formatted string, or empty string if None

    Example:
        >>> format_datetime_iso(datetime(2025, 1, 1, 12, 0))
        '2025-01-01T12:00:00'
        >>> format_datetime_iso(None)
        ''
    """
    if dt is None:
        return ''
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)