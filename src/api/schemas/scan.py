"""
Pydantic schemas for scan-related operations.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domain": "example.com",
            "timeout": 300
        }
    })

    domain: str = Field(..., description="Domain to scan")
    timeout: Optional[int] = Field(300, description="Scan timeout in seconds")


class BatchScanCreate(BaseModel):
    """Schema for creating a batch scan."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "primary_only": True,
            "timeout": 300
        }
    })

    primary_only: bool = Field(default=False, description="Scan only primary domains")
    timeout: Optional[int] = Field(300, description="Scan timeout in seconds per domain")


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

    scan_id: str
    domain: Optional[str] = None  # Made optional, computed from domains array
    scan_type: str
    tool_name: Optional[str] = None  # Made optional, may not be set
    status: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    findings_count: int = 0


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
                {"subdomain": "api.example.com", "port": 443, "protocol": "tcp", "ip": "192.168.1.1", "discovered_at": "2025-01-20T15:02:00"}
            ]
        }
    })

    scan: ScanResponse
    subdomains: List[SubdomainResult]
    ports: List[PortResult]


class ScanListResponse(BaseModel):
    """Schema for scan list response."""
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
            "total": 1
        }
    })

    scans: List[ScanResponse]
    total: int
