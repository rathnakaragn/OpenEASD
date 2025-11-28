"""
Base Detector class for OpenEASD Analysis Layer.

All vulnerability detectors inherit from this base class to ensure
consistent interface and behavior.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BaseDetector(ABC):
    """Abstract base class for all vulnerability detectors."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize detector with configuration.

        Args:
            config: Detector-specific configuration
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)

    @abstractmethod
    def analyze(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze scan data and return findings.

        Args:
            scan_data: Dictionary containing scan results from tools
                May include: subfinder_results, naabu_results, dnsx_results, httpx_results

        Returns:
            List of finding dictionaries, each containing:
            - finding_type: Type of finding (e.g., 'database_port_exposed')
            - title: Human-readable title
            - description: Detailed description
            - affected_asset: Domain/subdomain/IP affected
            - severity_hint: Suggested severity (can be overridden by scorer)
            - evidence: Technical evidence (optional)
            - port: Port number (for network findings)
            - cwe_id: CWE identifier (optional)
        """
        pass

    def is_enabled(self) -> bool:
        """Check if detector is enabled."""
        return self.enabled

    def get_name(self) -> str:
        """Get detector name."""
        return self.__class__.__name__

    def _create_finding(
        self,
        finding_type: str,
        title: str,
        description: str,
        affected_asset: str,
        severity_hint: str = 'medium',
        **kwargs
    ) -> Dict[str, Any]:
        """
        Helper method to create standardized finding dictionary.

        Args:
            finding_type: Type of finding
            title: Human-readable title
            description: Detailed description
            affected_asset: Asset identifier
            severity_hint: Suggested severity level
            **kwargs: Additional fields (port, cwe_id, evidence, etc.)

        Returns:
            Standardized finding dictionary
        """
        finding = {
            'finding_type': finding_type,
            'title': title,
            'description': description,
            'affected_asset': affected_asset,
            'severity_hint': severity_hint,
            'detector': self.get_name()
        }

        # Add any additional fields
        finding.update(kwargs)

        return finding
