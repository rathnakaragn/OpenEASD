"""
CVE Severity Mapping Service

Provides CVSS scores and severity levels for known CVEs.
Extensible for integration with external CVE databases (NVD, CVE.org).
"""

import logging
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


class CVESeverityService:
    """Service for managing CVE severity information."""

    # Known CVE database - can be extended or loaded from external source
    CVE_DATABASE = {
        # MySQL
        'CVE-2012-2122': {
            'severity': 'critical',
            'cvss': 9.8,
            'description': 'MySQL Authentication Bypass',
            'affected_versions': ['5.0.0-5.0.76', '5.1.0-5.1.36', '5.5.0-5.5.16']
        },
        'CVE-2016-6663': {
            'severity': 'high',
            'cvss': 7.5,
            'description': 'MySQL Privilege Escalation',
            'affected_versions': ['5.6.x', '5.7.0-5.7.15']
        },
        'CVE-2019-2627': {
            'severity': 'high',
            'cvss': 8.4,
            'description': 'MySQL Privilege Escalation',
            'affected_versions': ['5.7.x', '8.0.0-8.0.14']
        },
        'CVE-2021-2109': {
            'severity': 'high',
            'cvss': 8.8,
            'description': 'MySQL Server Security Feature Bypass',
            'affected_versions': ['5.7.0-5.7.31', '8.0.0-8.0.20']
        },

        # PostgreSQL
        'CVE-2019-10128': {
            'severity': 'high',
            'cvss': 8.1,
            'description': 'PostgreSQL Privilege Escalation',
            'affected_versions': ['9.4.0-9.4.26', '10.0-10.15', '11.0-11.10', '12.0-12.5']
        },
        'CVE-2021-3393': {
            'severity': 'high',
            'cvss': 8.8,
            'description': 'PostgreSQL libpq Security Vulnerability',
            'affected_versions': ['9.2.0-13.x']
        },

        # Redis
        'CVE-2015-8080': {
            'severity': 'critical',
            'cvss': 9.8,
            'description': 'Redis Unauthenticated Access',
            'affected_versions': ['2.x', '3.x']
        },

        # MongoDB
        'CVE-2020-7928': {
            'severity': 'critical',
            'cvss': 9.8,
            'description': 'MongoDB Authentication Bypass',
            'affected_versions': ['3.6.0-4.2.x']
        },

        # Other critical CVEs
        'CVE-2014-6271': {
            'severity': 'critical',
            'cvss': 10.0,
            'description': 'Bash ShellShock Vulnerability',
            'affected_versions': ['Bash 3.x-4.3']
        },
        'CVE-2021-44228': {
            'severity': 'critical',
            'cvss': 10.0,
            'description': 'Apache Log4j Remote Code Execution',
            'affected_versions': ['2.0-2.14.1']
        },
    }

    @classmethod
    def get_severity(cls, cve_id: str) -> Dict[str, Any]:
        """
        Get severity information for a CVE.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2012-2122')

        Returns:
            Dictionary with keys:
            - severity: 'critical', 'high', 'medium', 'low', 'info'
            - cvss: CVSS score (0-10)
            - description: Vulnerability description
            - affected_versions: List of affected versions (optional)
        """
        if cve_id in cls.CVE_DATABASE:
            return cls.CVE_DATABASE[cve_id]

        # Safe default for unknown CVEs
        logger.debug(f"Unknown CVE {cve_id}, using default severity")
        return {
            'severity': 'medium',
            'cvss': 5.0,
            'description': 'Known vulnerability (details unavailable)',
            'source': 'default'
        }

    @classmethod
    def is_known(cls, cve_id: str) -> bool:
        """Check if a CVE is in the known database."""
        return cve_id in cls.CVE_DATABASE

    @classmethod
    def add_cve(cls, cve_id: str, severity: str, cvss: float, description: str) -> None:
        """
        Add or update a CVE in the database.

        Args:
            cve_id: CVE ID
            severity: Severity level
            cvss: CVSS score (0-10)
            description: Vulnerability description
        """
        cls.CVE_DATABASE[cve_id] = {
            'severity': severity,
            'cvss': cvss,
            'description': description
        }
        logger.info(f"Added/updated CVE {cve_id} to database")

    @classmethod
    def load_from_file(cls, filepath: str) -> None:
        """
        Load CVE database from JSON file.

        File format:
        {
            "CVE-2024-1234": {
                "severity": "critical",
                "cvss": 9.8,
                "description": "..."
            }
        }

        Args:
            filepath: Path to CVE database JSON file
        """
        import json
        try:
            with open(filepath, 'r') as f:
                external_db = json.load(f)
                cls.CVE_DATABASE.update(external_db)
                logger.info(f"Loaded {len(external_db)} CVEs from {filepath}")
        except Exception as e:
            logger.warning(f"Failed to load CVE database from {filepath}: {e}")
