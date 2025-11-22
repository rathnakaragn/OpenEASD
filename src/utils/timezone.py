"""
Timezone utilities for OpenEASD API.

Handles conversion of datetime objects to IST (Indian Standard Time)
and formatting with 24-hour format.
"""

import pytz
from datetime import datetime
from typing import Optional


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


def format_ist_datetime(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime as IST string in 24-hour format.
    
    Args:
        dt: Datetime object to format
        
    Returns:
        Formatted string as "YYYY-MM-DD HH:MM:SS IST" or None if input is None
    """
    if dt is None:
        return None
    
    # Convert to IST first
    ist_dt = to_ist(dt)
    
    # Format in 24-hour format with IST suffix
    return ist_dt.strftime('%Y-%m-%d %H:%M:%S IST')


def utc_to_ist(utc_dt: datetime) -> datetime:
    """
    Convert UTC datetime to IST.
    
    Args:
        utc_dt: UTC datetime object
        
    Returns:
        Datetime object in IST timezone
    """
    if utc_dt.tzinfo is None:
        utc_dt = pytz.UTC.localize(utc_dt)
    
    return utc_dt.astimezone(IST)


class ISTDatetime:
    """Helper class for IST datetime operations."""
    
    @staticmethod
    def now() -> datetime:
        """Get current IST datetime."""
        return get_ist_now()
    
    @staticmethod
    def from_utc(utc_dt: datetime) -> datetime:
        """Convert UTC to IST."""
        return utc_to_ist(utc_dt)
    
    @staticmethod
    def format(dt: datetime) -> str:
        """Format datetime as IST string."""
        return format_ist_datetime(dt) or ""