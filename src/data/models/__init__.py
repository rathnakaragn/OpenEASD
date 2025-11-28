"""
SQLModel models for OpenEASD.

Note: Finding, Vulnerability, CVEMapping, and FindingGroup models
have been moved to the Analysis Layer (src/analysis/models.py).
SecurityAlert model has been deprecated in favor of Finding.
"""

from .domain import Domain
from .scan import ScanSession
from .subdomain import SubdomainHistory
from .tool_results import SubfinderResult, AmassResult, NmapResult, NaabuResult
from .api_key import APIKey
from .audit_log import AuditLog

# Import from analysis layer for backward compatibility
from src.analysis.models import Finding, Vulnerability, CVEMapping, FindingGroup

__all__ = [
    'Domain',
    'ScanSession',
    'SubdomainHistory',
    'SubfinderResult',
    'AmassResult',
    'NmapResult',
    'NaabuResult',
    'Finding',  # From analysis layer
    'Vulnerability',  # From analysis layer
    'CVEMapping',  # From analysis layer
    'FindingGroup',  # From analysis layer
    'APIKey',
    'AuditLog',
]
