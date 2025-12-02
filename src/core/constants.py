"""
Core constants for OpenEASD.

This module defines application-wide constants to eliminate magic numbers
and string literals throughout the codebase.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from enum import Enum
from typing import Dict, Any


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


# Set of valid finding statuses for validation
VALID_FINDING_STATUSES = {status.value for status in FindingStatus}


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


# Severity ordering for comparisons (higher index = more severe)
SEVERITY_ORDER = [
    Severity.INFO.value,
    Severity.LOW.value,
    Severity.MEDIUM.value,
    Severity.HIGH.value,
    Severity.CRITICAL.value,
]


# Severity display icons for CLI output
SEVERITY_ICONS = {
    Severity.CRITICAL.value: "[C]",
    Severity.HIGH.value: "[H]",
    Severity.MEDIUM.value: "[M]",
    Severity.LOW.value: "[L]",
    Severity.INFO.value: "[I]",
}


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


# Risk scoring weights (must sum to 1.0)
class RiskWeights:
    """Weights for risk score calculation components."""
    BASE_SCORE = 0.4      # Inherent risk of finding type
    CONTEXT_SCORE = 0.4   # Business context and asset criticality
    EXPOSURE_SCORE = 0.2  # Public accessibility and exposure


# Maximum scores for each component
class RiskMaxScores:
    """Maximum possible scores for each risk component."""
    BASE_MAX = 40
    CONTEXT_MAX = 40
    EXPOSURE_MAX = 20
    TOTAL_MAX = 100


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


# ============================================================================
# Finding Type Constants
# ============================================================================

class FindingType(str, Enum):
    """Types of security findings."""
    OPEN_PORT = "open_port"
    DATABASE_EXPOSURE = "database_exposure"
    ADMIN_INTERFACE = "admin_interface"
    REMOTE_ACCESS = "remote_access"
    UNENCRYPTED_PROTOCOL = "unencrypted_protocol"
    HIGH_RISK_SERVICE = "high_risk_service"
    MEDIUM_RISK_SERVICE = "medium_risk_service"
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    SERVICE_DETECTION = "service_detection"
    VULNERABILITY = "vulnerability"


# ============================================================================
# Scan Status Constants
# ============================================================================

class ScanStatus(str, Enum):
    """Scan execution status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ============================================================================
# Tool Names
# ============================================================================

class ToolName(str, Enum):
    """Security tools integrated in OpenEASD."""
    SUBFINDER = "subfinder"
    AMASS = "amass"
    NMAP = "nmap"
    NAABU = "naabu"
    DNSX = "dnsx"
    HTTPX = "httpx"
    TLSX = "tlsx"


# ============================================================================
# Output Format Constants
# ============================================================================

class OutputFormat(str, Enum):
    """Supported output formats for CLI."""
    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    TXT = "txt"


# ============================================================================
# Scan Frequency Constants
# ============================================================================

class ScanFrequency(str, Enum):
    """Domain scan frequency options."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    MANUAL = "manual"


# ============================================================================
# Evidence Field Names (for JSON storage)
# ============================================================================

class EvidenceFields:
    """Standard field names for finding evidence JSON."""
    CVE_IDS = "cve_ids"
    CVSS_SCORE = "cvss_score"
    CVSS_VECTOR = "cvss_vector"
    SERVICE_NAME = "service_name"
    SERVICE_VERSION = "service_version"
    BANNER = "banner"
    TLS_VERSION = "tls_version"
    CERTIFICATE_INFO = "certificate_info"
    HTTP_HEADERS = "http_headers"
    RESPONSE_CODE = "response_code"


# ============================================================================
# Database Pagination Defaults
# ============================================================================

class PaginationDefaults:
    """Default pagination settings."""
    DEFAULT_LIMIT = 100
    MAX_LIMIT = 1000
    DEFAULT_OFFSET = 0


# ============================================================================
# Timeout Constants (in seconds)
# ============================================================================

class TimeoutDefaults:
    """Default timeout values for various operations."""
    TOOL_EXECUTION = 300      # 5 minutes
    SUBFINDER = 120           # 2 minutes
    NAABU = 300               # 5 minutes
    DNSX = 60                 # 1 minute
    HTTPX = 60                # 1 minute
    TLSX = 60                 # 1 minute
    ANALYSIS = 600            # 10 minutes


# ============================================================================
# Confidence Level Constants
# ============================================================================

class ConfidenceLevel(str, Enum):
    """Finding confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================================
# Helper Functions
# ============================================================================

def get_severity_from_score(score: int) -> str:
    """
    Convert risk score to severity level.

    Args:
        score: Risk score (0-100)

    Returns:
        Severity level string
    """
    if score >= RiskThresholds.CRITICAL_MIN:
        return Severity.CRITICAL.value
    elif score >= RiskThresholds.HIGH_MIN:
        return Severity.HIGH.value
    elif score >= RiskThresholds.MEDIUM_MIN:
        return Severity.MEDIUM.value
    elif score >= RiskThresholds.LOW_MIN:
        return Severity.LOW.value
    else:
        return Severity.INFO.value


def compare_severity(severity1: str, severity2: str) -> int:
    """
    Compare two severity levels.

    Args:
        severity1: First severity level
        severity2: Second severity level

    Returns:
        -1 if severity1 < severity2
         0 if severity1 == severity2
         1 if severity1 > severity2
    """
    try:
        idx1 = SEVERITY_ORDER.index(severity1)
        idx2 = SEVERITY_ORDER.index(severity2)
        return (idx1 > idx2) - (idx1 < idx2)
    except ValueError:
        return 0
