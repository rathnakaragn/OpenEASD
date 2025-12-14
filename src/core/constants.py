"""
Core constants for OpenEASD.

This module defines application-wide constants to eliminate magic numbers
and string literals throughout the codebase.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from enum import Enum


# ============================================================================
# Finding Status Constants
# ============================================================================

class FindingStatus(str, Enum):
    """Valid finding status values."""
    NEW = "new"
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


# ============================================================================
# Severity Level Constants
# ============================================================================

class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# Risk Scoring Constants
# ============================================================================

class RiskThresholds:
    """Default risk score thresholds for severity classification."""
    CRITICAL_MIN = 80
    HIGH_MIN = 60
    MEDIUM_MIN = 40
    LOW_MIN = 20
    # Below LOW_MIN is INFO


# ============================================================================
# Port Risk Classifications
# ============================================================================

class PortRisk(str, Enum):
    """Port risk classification levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Common port categories
class PortCategory(str, Enum):
    """Port service categories."""
    DATABASE = "database"
    ADMIN = "admin"
    REMOTE_ACCESS = "remote_access"
    WEB = "web"
    EMAIL = "email"
    FILE_TRANSFER = "file_transfer"
    ENCRYPTION = "encryption"
    OTHER = "other"
