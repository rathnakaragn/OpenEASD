"""
Analysis Layer for OpenEASD.

Transforms raw scan data into actionable security intelligence with:
- Risk scoring and prioritization
- Vulnerability detection
- CVE enrichment
- Finding deduplication
- Remediation guidance
- Unified alert and finding management

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from src.analysis.analysis_service import AnalysisService
from src.analysis.alert_service import AlertManagementService
from src.analysis.models import Finding, Vulnerability, CVEMapping, FindingGroup

__all__ = [
    'AnalysisService',
    'AlertManagementService',
    'Finding',
    'Vulnerability',
    'CVEMapping',
    'FindingGroup'
]
