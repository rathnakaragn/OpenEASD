"""
Analysis Layer Models - Re-export Module.

DEPRECATION NOTICE: The Finding, Vulnerability, CVEMapping, and FindingGroup
models have been moved to the Data Layer (src/data/models/finding.py) to fix
an architectural violation where Database Layer was importing from Analysis Layer.

This module re-exports the models from the Data Layer for backwards compatibility.
New code should import from:
    from src.data.models.finding import Finding, Vulnerability, CVEMapping, FindingGroup
or:
    from src.data.models import Finding, Vulnerability, CVEMapping, FindingGroup

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
Updated: December 2025 (converted to re-export module)
"""

# Re-export from Data Layer for backwards compatibility
from src.data.models.finding import Finding, Vulnerability, CVEMapping, FindingGroup

__all__ = ['Finding', 'Vulnerability', 'CVEMapping', 'FindingGroup']
