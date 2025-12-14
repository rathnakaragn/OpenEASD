"""
Pydantic schemas for findings API endpoints.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

from src.api.schemas.common import FindingStatus, Severity


class FindingBase(BaseModel):
    """Base schema for finding data."""

    finding_type: str = Field(..., description="Type of finding (e.g., 'database_port_exposed')")
    affected_asset: str = Field(..., description="Domain/subdomain/IP affected")
    port: Optional[int] = Field(None, description="Port number (for network findings)")
    protocol: Optional[str] = Field(None, description="Protocol (tcp/udp)")
    title: str = Field(..., description="Human-readable title")
    description: Optional[str] = Field(None, description="Detailed description")
    service_name: Optional[str] = Field(None, description="Service name")
    severity: Severity = Field(..., description="Severity level (critical/high/medium/low/info)")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score (0-100)")
    confidence_level: Optional[str] = Field("medium", description="Confidence level (high/medium/low)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    detector: Optional[str] = Field(None, description="Detector that found this issue")


class FindingResponse(FindingBase):
    """Response schema for a single finding."""

    id: str = Field(..., description="Finding UUID")
    scan_id: str = Field(..., description="Scan session UUID")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Technical evidence")
    score_breakdown: Optional[Dict[str, Any]] = Field(default=None, description="Score breakdown")
    status: FindingStatus = Field(
        default=FindingStatus.NEW,
        description="Status (new/open/acknowledged/resolved/reopened/false_positive)"
    )
    false_positive: bool = Field(default=False, description="Marked as false positive")
    resolved_at: Optional[datetime] = Field(None, description="When finding was resolved")
    reopened_at: Optional[datetime] = Field(None, description="When finding was reopened")
    resolution_notes: Optional[str] = Field(None, description="Resolution notes")
    first_seen: Optional[datetime] = Field(None, description="When finding was first discovered")
    last_seen: Optional[datetime] = Field(None, description="When finding was last detected")
    occurrence_count: int = Field(default=1, description="Number of times detected across scans")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    """Response schema for list of findings."""

    findings: List[FindingResponse] = Field(..., description="List of findings")
    total_count: int = Field(..., description="Total number of findings")
    has_more: bool = Field(..., description="More results available")
    limit: int = Field(..., description="Results per page")
    offset: int = Field(..., description="Current offset")


class FindingStatisticsResponse(BaseModel):
    """Response schema for finding statistics."""

    total_findings: int = Field(..., description="Total number of findings")
    by_severity: Dict[str, int] = Field(..., description="Count by severity level")
    by_status: Dict[str, int] = Field(..., description="Count by status")
    average_risk_score: float = Field(..., description="Average risk score")
    # Severity breakdown
    critical_findings: int = Field(..., description="Number of critical findings")
    high_findings: int = Field(..., description="Number of high findings")
    medium_findings: int = Field(..., description="Number of medium findings")
    low_findings: int = Field(..., description="Number of low findings")
    info_findings: int = Field(..., description="Number of info findings")
    # Full status lifecycle
    new_findings: int = Field(default=0, description="Number of new findings")
    open_findings: int = Field(..., description="Number of open findings")
    acknowledged_findings: int = Field(default=0, description="Number of acknowledged findings")
    resolved_findings: int = Field(..., description="Number of resolved findings")
    reopened_findings: int = Field(default=0, description="Number of reopened findings")
    false_positives: int = Field(..., description="Number of false positives")
    # Aggregate counts
    active_findings: int = Field(default=0, description="Number of active findings (new+open+acknowledged+reopened)")
    closed_findings: int = Field(default=0, description="Number of closed findings (resolved+false_positive)")


class FindingStatusUpdate(BaseModel):
    """Request schema for updating finding status."""

    status: FindingStatus = Field(
        ...,
        description="New status (new/open/acknowledged/resolved/reopened/false_positive)"
    )
    resolution_notes: Optional[str] = Field(None, description="Optional resolution notes")


class AnalysisResultResponse(BaseModel):
    """Response schema for analysis results."""

    scan_id: str = Field(..., description="Scan session UUID")
    findings_count: int = Field(..., description="Number of findings")
    findings: List[FindingResponse] = Field(..., description="List of findings")
    statistics: FindingStatisticsResponse = Field(..., description="Analysis statistics")
    analysis_timestamp: str = Field(..., description="When analysis was performed")
