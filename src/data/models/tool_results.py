"""
Tool Result SQLModels.
"""

from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel


class SubfinderResult(SQLModel, table=True):
    """Subfinder scan results."""

    __tablename__ = "subfinder_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(max_length=255)
    apex_domain: str = Field(max_length=255)
    subdomain: str = Field(max_length=255)
    source: Optional[str] = Field(default=None, max_length=100)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None


class AmassResult(SQLModel, table=True):
    """Amass scan results."""

    __tablename__ = "amass_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(max_length=255)
    apex_domain: str = Field(max_length=255)
    subdomain: str = Field(max_length=255)
    source: Optional[str] = Field(default=None, max_length=100)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None


class NmapResult(SQLModel, table=True):
    """Nmap scan results."""

    __tablename__ = "nmap_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(max_length=255)
    target_host: str = Field(max_length=255)
    port: int
    protocol: str = Field(max_length=20)
    service_name: Optional[str] = Field(default=None, max_length=100)
    service_version: Optional[str] = Field(default=None, max_length=255)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None


class NaabuResult(SQLModel, table=True):
    """Naabu scan results."""

    __tablename__ = "naabu_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(max_length=255)
    target_host: str = Field(max_length=255)
    port: int
    protocol: str = Field(max_length=20)
    ip: Optional[str] = Field(default=None, max_length=45)  # IPv4/IPv6 address
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None
