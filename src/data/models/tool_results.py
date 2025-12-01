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
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )  # Index for scan-based queries
    apex_domain: str = Field(
        foreign_key="domains.domain",
        index=True,
        max_length=255
    )  # Index for domain filtering
    subdomain: str = Field(index=True, max_length=255)  # Index for subdomain lookups
    source: Optional[str] = Field(default=None, max_length=100)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None


class AmassResult(SQLModel, table=True):
    """Amass scan results."""

    __tablename__ = "amass_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )  # Index for scan-based queries
    apex_domain: str = Field(
        foreign_key="domains.domain",
        index=True,
        max_length=255
    )  # Index for domain filtering
    subdomain: str = Field(index=True, max_length=255)  # Index for subdomain lookups
    source: Optional[str] = Field(default=None, max_length=100)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None


class NmapResult(SQLModel, table=True):
    """Nmap scan results."""

    __tablename__ = "nmap_results"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )  # Index for scan-based queries
    target_host: str = Field(index=True, max_length=255)  # Index for host filtering
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
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )  # Index for scan-based queries
    target_host: str = Field(index=True, max_length=255)  # Index for host filtering
    port: int
    protocol: str = Field(max_length=20)
    ip: Optional[str] = Field(default=None, max_length=45)  # IPv4/IPv6 address
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_json: Optional[str] = None
