"""
Finding and Analysis SQLModels for OpenEASD Analysis Layer.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class Finding(SQLModel, table=True):
    """
    Security finding discovered during analysis.

    Findings are the core output of the Analysis Layer, representing
    potential security issues detected by various detectors.
    """

    __tablename__ = "findings"

    # Primary identification
    id: str = Field(primary_key=True, max_length=255)  # UUID
    scan_id: str = Field(index=True, max_length=255)   # Links to scan_sessions
    finding_type: str = Field(index=True, max_length=100)  # e.g., 'database_port_exposed'

    # Asset information
    affected_asset: str = Field(index=True, max_length=255)  # Domain/subdomain/IP
    port: Optional[int] = Field(default=None)  # For network findings
    protocol: Optional[str] = Field(default=None, max_length=20)

    # Finding details
    title: str = Field(max_length=500)
    description: Optional[str] = None  # TEXT field
    service_name: Optional[str] = Field(default=None, max_length=100)

    # Risk assessment
    severity: str = Field(index=True, max_length=20)  # critical/high/medium/low/info
    risk_score: int = Field(default=50)  # 0-100
    confidence_level: Optional[str] = Field(default='medium', max_length=20)  # high/medium/low

    # Evidence and metadata
    evidence_json: Optional[str] = None  # JSON string with technical evidence
    cwe_id: Optional[str] = Field(default=None, max_length=50)
    remediation: Optional[str] = None  # TEXT field
    detector: Optional[str] = Field(default=None, max_length=100)  # Which detector found it

    # Scoring breakdown (for transparency)
    score_breakdown_json: Optional[str] = None  # JSON: {base, context, exposure, total}

    # Status tracking
    status: str = Field(default='open', max_length=20)  # open/acknowledged/resolved/false_positive
    false_positive: bool = Field(default=False)
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None

    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Vulnerability(SQLModel, table=True):
    """
    CVE-enriched vulnerability record.

    Links findings to known CVE records and provides additional
    vulnerability intelligence.
    """

    __tablename__ = "vulnerabilities"

    # Primary identification
    id: str = Field(primary_key=True, max_length=255)  # UUID
    cve_id: str = Field(unique=True, index=True, max_length=50)  # e.g., 'CVE-2024-1234'

    # CVE details
    description: Optional[str] = None  # TEXT: CVE description
    severity: str = Field(default='medium', max_length=20)  # critical/high/medium/low
    cvss_score: Optional[float] = None  # CVSS base score (0.0-10.0)
    cvss_vector: Optional[str] = Field(default=None, max_length=255)

    # Classification
    cwe_id: Optional[str] = Field(default=None, max_length=50)
    vulnerability_type: Optional[str] = Field(default=None, max_length=100)

    # Affected components
    affected_products_json: Optional[str] = None  # JSON: List of affected products/versions
    affected_versions: Optional[str] = None  # TEXT: Version ranges

    # Exploit information
    exploit_available: bool = Field(default=False)
    exploit_maturity: Optional[str] = Field(default=None, max_length=50)  # functional/poc/high/unproven
    publicly_disclosed: bool = Field(default=False)

    # References and resources
    references_json: Optional[str] = None  # JSON: List of reference URLs
    patch_url: Optional[str] = None
    advisory_url: Optional[str] = None

    # Metadata
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class CVEMapping(SQLModel, table=True):
    """
    Maps findings to CVE records.

    A many-to-many relationship between findings and vulnerabilities,
    allowing a finding to be linked to multiple CVEs and vice versa.
    """

    __tablename__ = "cve_mappings"

    # Composite primary key
    id: str = Field(primary_key=True, max_length=255)  # UUID
    finding_id: str = Field(index=True, max_length=255)  # Foreign key to findings
    vulnerability_id: str = Field(index=True, max_length=255)  # Foreign key to vulnerabilities
    cve_id: str = Field(index=True, max_length=50)  # Denormalized for quick lookup

    # Mapping confidence
    confidence: str = Field(default='medium', max_length=20)  # high/medium/low
    match_type: Optional[str] = Field(default=None, max_length=50)  # exact/partial/related

    # Verification
    verified: bool = Field(default=False)
    verified_by: Optional[str] = Field(default=None, max_length=100)
    verified_at: Optional[datetime] = None

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None


class FindingGroup(SQLModel, table=True):
    """
    Groups related findings for better organization.

    Findings can be grouped by:
    - Same vulnerability across multiple assets
    - Related findings in a single asset
    - Campaign or attack pattern
    """

    __tablename__ = "finding_groups"

    # Primary identification
    id: str = Field(primary_key=True, max_length=255)  # UUID
    group_name: str = Field(max_length=255)
    group_type: str = Field(default='related', max_length=50)  # related/campaign/asset_specific

    # Group details
    description: Optional[str] = None
    affected_assets_json: Optional[str] = None  # JSON: List of affected assets
    finding_ids_json: Optional[str] = None  # JSON: List of finding IDs in this group

    # Risk assessment
    severity: str = Field(default='medium', max_length=20)
    total_findings: int = Field(default=0)
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)

    # Status
    status: str = Field(default='open', max_length=20)  # open/investigating/resolved
    priority: Optional[str] = Field(default=None, max_length=20)  # critical/high/medium/low

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
