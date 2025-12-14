"""
Pydantic schemas for scan-related operations.
"""

from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List
from datetime import datetime

from src.api.schemas.common import ScanStatus, validate_domain_format


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domain": "example.com",
            "timeout": 300
        }
    })

    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Domain to scan (e.g., example.com)"
    )
    timeout: Optional[int] = Field(
        default=300,
        ge=60,
        le=3600,
        description="Scan timeout in seconds (60-3600)"
    )

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format and normalize to lowercase."""
        return validate_domain_format(v)


class BatchScanCreate(BaseModel):
    """Schema for creating a batch scan."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "primary_only": True,
            "timeout": 300
        }
    })

    primary_only: bool = Field(default=False, description="Scan only primary domains")
    timeout: Optional[int] = Field(
        default=300,
        ge=60,
        le=3600,
        description="Scan timeout in seconds per domain (60-3600)"
    )


class ScanResponse(BaseModel):
    """Schema for scan response."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "scan_id": "scan_12345",
            "domain": "example.com",
            "scan_type": "passive_subdomain_enum",
            "tool_name": "subfinder",
            "status": "completed",
            "start_time": "2025-01-20T15:00:00",
            "end_time": "2025-01-20T15:05:00",
            "findings_count": 42
        }
    })

    scan_id: str = Field(..., description="Unique scan session identifier")
    domain: str = Field(..., description="Primary domain being scanned")
    scan_type: str = Field(default="passive_subdomain_enum", description="Type of scan performed")
    tool_name: Optional[str] = Field(None, description="Primary tool used for scanning")
    status: ScanStatus = Field(..., description="Scan status: pending, running, completed, failed")
    start_time: Optional[datetime] = Field(None, description="When scan started (null if pending)")
    end_time: Optional[datetime] = Field(None, description="When scan completed (null if not finished)")
    findings_count: int = Field(default=0, description="Number of security findings discovered")


class SubdomainResult(BaseModel):
    """Schema for subdomain result."""
    subdomain: str
    ip_address: str
    discovered_at: str


class PortResult(BaseModel):
    """Schema for port scan result."""
    subdomain: str
    port: int
    protocol: str
    ip: str
    discovered_at: str


class ScanResultsResponse(BaseModel):
    """Schema for scan results response."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "scan": {
                "scan_id": "scan_12345",
                "domain": "example.com",
                "status": "completed",
                "total_subdomains": 42,
                "total_ports": 15
            },
            "subdomains": [
                {"subdomain": "api.example.com", "ip_address": "192.168.1.1", "discovered_at": "2025-01-20T15:00:00"}
            ],
            "ports": [
                {
                    "subdomain": "api.example.com", "port": 443, "protocol": "tcp",
                    "ip": "192.168.1.1", "discovered_at": "2025-01-20T15:02:00"
                }
            ]
        }
    })

    scan: ScanResponse
    subdomains: List[SubdomainResult]
    ports: List[PortResult]


class ScanListResponse(BaseModel):
    """Schema for scan list response with pagination."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "scans": [
                {
                    "scan_id": "scan_12345",
                    "domain": "example.com",
                    "scan_type": "passive_subdomain_enum",
                    "status": "completed",
                    "findings_count": 42
                }
            ],
            "total_count": 1,
            "limit": 20,
            "offset": 0,
            "has_more": False
        }
    })

    scans: List[ScanResponse] = Field(..., description="List of scan sessions")
    total_count: int = Field(..., description="Total number of scans")
    limit: int = Field(default=20, description="Results per page")
    offset: int = Field(default=0, description="Current offset")
    has_more: bool = Field(default=False, description="More results available")


class BatchScanResponse(BaseModel):
    """Schema for batch scan response."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "scans": [
                {
                    "scan_id": "scan_12345",
                    "domain": "example.com",
                    "status": "pending"
                }
            ],
            "total_queued": 1,
            "message": "Queued 1 scans for processing"
        }
    })

    scans: List[ScanResponse] = Field(..., description="List of queued scan sessions")
    total_queued: int = Field(..., description="Number of scans queued")
    message: str = Field(..., description="Status message")


class ScanRetryRequest(BaseModel):
    """Schema for retry scan request."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "timeout": 300
        }
    })

    timeout: Optional[int] = Field(
        default=None,
        ge=60,
        le=3600,
        description="Override timeout in seconds (60-3600)"
    )
