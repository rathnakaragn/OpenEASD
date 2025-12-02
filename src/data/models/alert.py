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

    # Service detection fields (from nmap integration)
    service_type: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Detected service type (mysql, ssh, ftp, etc)"
    )
    service_version: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Service version string"
    )
    service_confidence: Optional[int] = Field(
        default=None,
        description="Nmap confidence level (0-100)"
    )
    detection_method: str = Field(
        default='httpx',
        max_length=50,
        description="Method used for detection: httpx, nmap, banner"
    )

    # CVE and vulnerability fields (from nmap NSE vulnerability detection)
    cve_ids: Optional[str] = Field(
        default=None,
        description="JSON list of CVE IDs found (e.g., '[\"CVE-2012-2122\", \"CVE-2016-6663\"]')"
    )
    cvss_score: Optional[float] = Field(
        default=None,
        description="Highest CVSS score among found CVEs (0-10)"
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        max_length=255,
        description="CVSS vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')"
    )
    vulnerability_description: Optional[str] = Field(
        default=None,
        description="Detailed description of vulnerabilities found"
    )
    remediation_steps: Optional[str] = Field(
        default=None,
        description="Steps to remediate vulnerabilities (e.g., upgrade to version X)"
    )

    discovered_at: datetime = Field(default_factory=datetime.utcnow)
