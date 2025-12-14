"""
Pydantic schemas for domain-related operations.
"""

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict, EmailStr
from typing import Optional, List
from datetime import datetime

from src.api.schemas.common import ScanFrequency, validate_domain_format


class SubdomainSummary(BaseModel):
    """Schema for subdomain summary information."""
    model_config = ConfigDict(from_attributes=True)

    subdomain: str = Field(..., description="Subdomain name")
    discovered_at: datetime = Field(..., description="When subdomain was first discovered")


class DomainCreate(BaseModel):
    """Schema for creating a new domain."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "domain": "example.com",
            "is_primary": True,
            "contact_email": "admin@example.com",
            "scan_frequency": "daily"
        }
    })

    domain: str = Field(..., description="Domain name (e.g., example.com)")
    is_primary: bool = Field(default=False, description="Mark as primary domain")
    contact_email: Optional[EmailStr] = Field(None, description="Contact email address")
    scan_frequency: Optional[ScanFrequency] = Field(None, description="Scan frequency (hourly, daily, weekly, monthly)")

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format and normalize to lowercase."""
        return validate_domain_format(v)


class DomainUpdate(BaseModel):
    """Schema for updating domain metadata."""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "is_primary": True
        }
    })

    is_primary: Optional[bool] = Field(None, description="Update primary status")
    contact_email: Optional[EmailStr] = Field(None, description="Update contact email")
    scan_frequency: Optional[ScanFrequency] = Field(None, description="Update scan frequency")

    @model_validator(mode='after')
    def check_at_least_one_field(self):
        """Ensure at least one field is provided for update."""
        if self.is_primary is None and self.contact_email is None and self.scan_frequency is None:
            raise ValueError('At least one field must be provided: is_primary, contact_email, or scan_frequency')
        return self


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
    active_scan: bool = Field(False, description="Whether active scanning is enabled for the domain")


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
                    "last_scanned_at": "2025-01-20T15:45:00",
                    "active_scan": True
                }
            ],
            "total_count": 1,
            "limit": 20,
            "offset": 0,
            "has_more": False
        }
    })

    domains: List[DomainResponse]
    total_count: int
    limit: int = Field(default=20, description="Results per page")
    offset: int = Field(default=0, description="Current offset")
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
    recent_subdomains: List[SubdomainSummary]


