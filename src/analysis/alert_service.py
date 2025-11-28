"""
Alert Management Service for OpenEASD Analysis Layer.

Consolidated service for creating, managing, and retrieving alerts/findings.
This replaces the previous split between SecurityAlert and Finding models.

All alerts are now stored as findings with full risk scoring and analysis metadata.
"""

import logging
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.utils.timezone import get_ist_now, to_ist

logger = logging.getLogger(__name__)


class AlertManagementService:
    """
    Manages security alerts and findings through the analysis layer.

    This service provides a unified interface for:
    - Creating alerts from scan results (converted to findings)
    - Managing alert lifecycle (open, acknowledged, resolved, false_positive)
    - Retrieving alerts with filtering and pagination
    - Generating alert statistics
    """

    def __init__(self, db_manager=None):
        """
        Initialize alert management service.

        Args:
            db_manager: Database manager instance (optional, for testing)
        """
        self.db_manager = db_manager
        logger.info("AlertManagementService initialized")

    def create_alert_from_scan(
        self,
        scan_id: str,
        domain: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        tool_source: str,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        confidence_level: str = "medium",
        remediation: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create an alert from scan results.

        This converts scan findings into structured findings for the analysis layer.

        Args:
            scan_id: Scan session UUID
            domain: Domain/subdomain affected
            vulnerability_type: Type of vulnerability (open_port, subdomain_discovered, etc.)
            severity: Severity level (critical, high, medium, low, info)
            description: Human-readable description
            tool_source: Tool that discovered it (subfinder, naabu, dnsx, etc.)
            port: Port number (for network findings)
            protocol: Protocol (tcp, udp)
            confidence_level: Confidence level (high, medium, low)
            remediation: Optional remediation guidance

        Returns:
            Dictionary containing created alert/finding data
        """
        finding_id = str(uuid.uuid4())

        # Map vulnerability types to finding types
        finding_type_map = {
            'open_port': 'port_exposed',
            'subdomain_discovered': 'subdomain_discovered',
            'dns_misconfiguration': 'dns_misconfiguration',
            'tls_weakness': 'tls_weakness',
            'web_vulnerability': 'web_vulnerability'
        }

        finding_type = finding_type_map.get(vulnerability_type, vulnerability_type)

        # Build finding record
        finding = {
            'id': finding_id,
            'scan_id': scan_id,
            'finding_type': finding_type,
            'affected_asset': domain,
            'title': description,
            'description': description,
            'severity': severity,
            'risk_score': self._calculate_risk_score(severity),
            'confidence_level': confidence_level,
            'port': port,
            'protocol': protocol,
            'service_name': None,
            'cwe_id': None,
            'remediation': remediation,
            'detector': tool_source,
            'evidence': {
                'tool_source': tool_source,
                'vulnerability_type': vulnerability_type
            },
            'score_breakdown': {
                'base_score': self._get_base_score(severity),
                'context_score': 20,  # Default context score
                'exposure_score': 10  # Default exposure score
            },
            'status': 'open',
            'false_positive': False,
            'discovered_at': get_ist_now(),
            'updated_at': get_ist_now()
        }

        return finding

    def create_alert_batch(
        self,
        scan_id: str,
        alerts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Create multiple alerts from scan results.

        Args:
            scan_id: Scan session UUID
            alerts: List of alert dictionaries

        Returns:
            List of created finding records
        """
        findings = []

        for alert in alerts:
            finding = self.create_alert_from_scan(
                scan_id=scan_id,
                domain=alert.get('domain'),
                vulnerability_type=alert.get('vulnerability_type'),
                severity=alert.get('severity'),
                description=alert.get('description'),
                tool_source=alert.get('tool_source'),
                port=alert.get('port'),
                protocol=alert.get('protocol'),
                confidence_level=alert.get('confidence_level', 'medium'),
                remediation=alert.get('remediation')
            )
            findings.append(finding)

        return findings

    def store_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """
        Store alerts as findings in the database.

        Args:
            alerts: List of alert dictionaries
        """
        if not self.db_manager:
            logger.warning("No database manager available, skipping storage")
            return

        try:
            # Store all alerts as findings
            self.db_manager.store_findings(alerts)
            logger.info(f"Stored {len(alerts)} alerts as findings")
        except Exception as e:
            logger.error(f"Failed to store alerts: {e}", exc_info=True)
            raise

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity_filter: Optional[List[str]] = None,
        severity: Optional[str] = None,
        domain: Optional[str] = None,
        scan_id: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retrieve alerts with filtering and pagination.

        Args:
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            severity_filter: List of severity levels to filter by
            severity: Single severity level to filter by
            domain: Filter by domain
            scan_id: Filter by scan ID
            min_severity: Minimum severity level (excludes below)

        Returns:
            Dictionary with alerts list, total count, and pagination info
        """
        if not self.db_manager:
            logger.warning("No database manager available")
            return {
                'findings': [],
                'total_count': 0,
                'has_more': False,
                'limit': limit,
                'offset': offset
            }

        try:
            result = self.db_manager.get_findings(
                limit=limit,
                offset=offset,
                affected_asset=domain,
                scan_id=scan_id,
                min_severity=min_severity
            )

            # Convert findings to alert format for backward compatibility
            findings = result.get('findings', [])
            alerts = [self._finding_to_alert(f) for f in findings]

            return {
                'alerts': alerts,
                'findings': findings,  # Also include raw findings
                'total': result.get('total_count', 0),
                'total_count': result.get('total_count', 0),
                'has_more': result.get('has_more', False),
                'limit': limit,
                'offset': offset
            }

        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}", exc_info=True)
            raise

    def get_alert_by_id(self, alert_id: str) -> Dict[str, Any]:
        """
        Get a specific alert by ID.

        Args:
            alert_id: Alert/Finding ID

        Returns:
            Alert/Finding dictionary

        Raises:
            ValueError: If alert not found
        """
        if not self.db_manager:
            raise ValueError("No database manager available")

        try:
            finding = self.db_manager.get_finding_by_id(alert_id)

            if not finding:
                raise ValueError(f"Alert not found: {alert_id}")

            alert = self._finding_to_alert(finding)
            return {'alert': alert, 'finding': finding}

        except Exception as e:
            logger.error(f"Error retrieving alert {alert_id}: {e}", exc_info=True)
            raise

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics.

        Returns:
            Dictionary containing statistics by severity, type, detector, etc.
        """
        if not self.db_manager:
            return {
                'total': 0,
                'by_severity': {},
                'by_type': {},
                'by_tool': {},
                'by_detector': {}
            }

        try:
            stats = self.db_manager.get_findings_statistics()

            return {
                'total': stats.get('total_findings', 0),
                'by_severity': {
                    'critical': stats.get('critical_findings', 0),
                    'high': stats.get('high_findings', 0),
                    'medium': stats.get('medium_findings', 0),
                    'low': stats.get('low_findings', 0),
                    'info': stats.get('info_findings', 0)
                },
                'by_status': stats.get('by_status', {}),
                'by_type': stats.get('by_type', {}),  # Finding types
                'by_tool': stats.get('by_detector', {}),  # Map detector to tool
                'by_detector': stats.get('by_detector', {}),  # Will be populated from findings
                'critical_findings': stats.get('critical_findings', 0),
                'high_findings': stats.get('high_findings', 0),
                'medium_findings': stats.get('medium_findings', 0),
                'low_findings': stats.get('low_findings', 0),
                'info_findings': stats.get('info_findings', 0)
            }

        except Exception as e:
            logger.error(f"Error retrieving alert statistics: {e}", exc_info=True)
            raise

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """
        Update alert status.

        Args:
            alert_id: Alert/Finding ID
            status: New status (open, acknowledged, resolved, false_positive)
            resolution_notes: Optional notes about resolution

        Returns:
            True if update successful, False otherwise
        """
        if not self.db_manager:
            return False

        try:
            success = self.db_manager.update_finding_status(
                finding_id=alert_id,
                status=status,
                resolution_notes=resolution_notes
            )
            return success
        except Exception as e:
            logger.error(f"Error updating alert status: {e}", exc_info=True)
            return False

    @staticmethod
    def _calculate_risk_score(severity: str) -> int:
        """
        Calculate risk score from severity level.

        Args:
            severity: Severity level (critical, high, medium, low, info)

        Returns:
            Risk score (0-100)
        """
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30,
            'info': 10
        }
        return severity_scores.get(severity.lower(), 50)

    @staticmethod
    def _get_base_score(severity: str) -> int:
        """
        Get base score from severity for score breakdown.

        Args:
            severity: Severity level

        Returns:
            Base score (0-40)
        """
        base_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10,
            'info': 5
        }
        return base_scores.get(severity.lower(), 20)

    @staticmethod
    def _finding_to_alert(finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert finding to alert format for backward compatibility.

        Args:
            finding: Finding dictionary

        Returns:
            Alert-formatted dictionary
        """
        return {
            'alert_id': finding.get('id'),
            'id': finding.get('id'),
            'scan_id': finding.get('scan_id'),
            'domain': finding.get('affected_asset'),
            'vulnerability_type': finding.get('finding_type'),
            'severity': finding.get('severity'),
            'description': finding.get('title') or finding.get('description'),
            'tool_source': finding.get('detector', ''),
            'discovered_at': finding.get('discovered_at'),
            'status': finding.get('status', 'open'),
            'remediation': finding.get('remediation'),
            'risk_score': finding.get('risk_score'),
            'confidence_level': finding.get('confidence_level')
        }
