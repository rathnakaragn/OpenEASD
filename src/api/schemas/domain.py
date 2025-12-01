"""
Pydantic schemas for domain-related operations.
"""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List
from datetime import datetime


class DomainCreate(BaseModel):
    """Schema for creating a new domain."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domain": "example.com",
            "is_primary": True,
            "scan_frequency": "daily"
        }
    })

    domain: str = Field(..., description="Domain name (e.g., example.com)")
    is_primary: bool = Field(default=False, description="Mark as primary domain")
    contact_email: Optional[str] = Field(None, description="Contact email")
    scan_frequency: Optional[str] = Field(None, description="Scan frequency (hourly, daily, weekly, monthly)")

    @field_validator('scan_frequency')
    @classmethod
    def validate_scan_frequency(cls, v):
        if v and v not in ['hourly', 'daily', 'weekly', 'monthly']:
            raise ValueError('scan_frequency must be one of: hourly, daily, weekly, monthly')
        return v


class DomainUpdate(BaseModel):
    """Schema for updating domain metadata."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "is_primary": True
        }
    })

    is_primary: Optional[bool] = Field(None, description="Update primary status")


class DomainResponse(BaseModel):
    """Schema for domain response."""
    model_config = ConfigDict(from_attributes=True)

    domain: str
    is_primary: bool
    scan_count: int
    contact_email: Optional[str] = None
    scan_frequency: Optional[str] = None
    created_at: Optional[datetime] = None
    last_scanned_at: Optional[datetime] = None


class DomainListResponse(BaseModel):
    """Schema for domain list response."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domains": [
                {
                    "domain": "example.com",
                    "is_primary": True,
                    "scan_count": 5,
                    "scan_frequency": "daily",
                    "created_at": "2025-01-15T10:30:00",
                    "last_scanned_at": "2025-01-20T15:45:00"
                }
            ],
            "total_count": 1,
            "has_more": False
        }
    })

    domains: List[DomainResponse]
    total_count: int
    has_more: bool


class DomainDetailResponse(DomainResponse):
    """Schema for detailed domain response."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domain": "example.com",
            "is_primary": True,
            "scan_count": 5,
            "subdomain_count": 42,
            "recent_subdomains": [
                {"subdomain": "api.example.com", "discovered_at": "2025-01-20T15:45:00"}
            ],
            "scan_frequency": "daily"
        }
    })

    subdomain_count: int
    recent_subdomains: List[dict]


class MessageResponse(BaseModel):
    """Schema for generic message response."""
    message: str
    details: Optional[dict] = None
