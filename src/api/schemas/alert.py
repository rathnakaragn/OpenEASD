"""
Pydantic schemas for alert-related operations.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime


class AlertResponse(BaseModel):
    """Schema for alert response."""
    alert_id: str
    scan_id: str
    domain: str
    vulnerability_type: str
    severity: str
    description: str
    tool_source: str
    discovered_at: str
    status: str = "open"

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert_12345",
                "scan_id": "scan_12345",
                "domain": "api.example.com",
                "vulnerability_type": "open_port",
                "severity": "low",
                "description": "Open port 443 (tcp)",
                "tool_source": "naabu",
                "discovered_at": "2025-01-20T15:02:00",
                "status": "open"
            }
        }


class AlertListResponse(BaseModel):
    """Schema for alert list response."""
    alerts: List[AlertResponse]
    total: int

    class Config:
        json_schema_extra = {
            "example": {
                "alerts": [
                    {
                        "alert_id": "alert_12345",
                        "scan_id": "scan_12345",
                        "domain": "api.example.com",
                        "vulnerability_type": "open_port",
                        "severity": "low",
                        "description": "Open port 443 (tcp)",
                        "tool_source": "naabu",
                        "discovered_at": "2025-01-20T15:02:00",
                        "status": "open"
                    }
                ],
                "total": 1
            }
        }


class AlertStatisticsResponse(BaseModel):
    """Schema for alert statistics response."""
    total: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    by_tool: Dict[str, int]

    class Config:
        json_schema_extra = {
            "example": {
                "total": 100,
                "by_severity": {
                    "critical": 2,
                    "high": 5,
                    "medium": 15,
                    "low": 50,
                    "info": 28
                },
                "by_type": {
                    "subdomain_discovered": 70,
                    "open_port": 25,
                    "dns_misconfiguration": 5
                },
                "by_tool": {
                    "subfinder": 70,
                    "naabu": 25,
                    "dnsx": 5
                }
            }
        }
