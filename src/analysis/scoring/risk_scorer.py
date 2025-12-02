"""
Risk Scoring Engine for OpenEASD Analysis Layer.

Implements deterministic risk scoring based on:
- Base Score (0-40): Inherent risk of the finding type
- Context Score (0-40): Business context and asset criticality
- Exposure Score (0-20): Public accessibility and active status

Total score: 0-100, mapped to severity levels (using RiskThresholds):
- 80-100: Critical
- 60-79:  High
- 40-59:  Medium
- 20-39:  Low
- 0-19:   Info

Refactored to use centralized constants from src/core/constants.py
and src/analysis/constants.py
"""

from typing import Dict, Any
from src.analysis.config import get_analysis_config
from src.core.constants import (
    Severity,
    RiskThresholds,
    FindingStatus,
    get_severity_from_score
)
from src.analysis.constants import KEYWORD_RISK_SCORES


class RiskScorer:
    """Deterministic risk scoring based on business impact."""

    def __init__(self):
        """Initialize risk scorer with configuration."""
        self.config = get_analysis_config()

        # Load scoring weights
        self.base_weight = self.config.get('analysis.scoring.base_score_weight', 0.4)
        self.context_weight = self.config.get('analysis.scoring.context_score_weight', 0.4)
        self.exposure_weight = self.config.get('analysis.scoring.exposure_score_weight', 0.2)

        # Load severity thresholds
        self.thresholds = self.config.get_severity_thresholds()

        # Define base risk scores for common finding types
        self.base_risk_map = {
            # Critical findings (35-40 points)
            'database_port_exposed': 40,
            'dns_takeover_vulnerable': 40,
            'credential_exposure': 40,
            'remote_code_execution': 40,

            # High findings (30-34 points)
            'expired_certificate': 32,
            'weak_tls_configuration': 30,
            'high_risk_port_exposed': 33,
            'web_misconfiguration': 35,
            'missing_security_headers': 28,

            # Medium findings (20-29 points)
            'medium_risk_port_exposed': 22,
            'subdomain_takeover_potential': 25,
            'open_directory_listing': 24,

            # Low findings (10-19 points)
            'subdomain_discovered': 10,
            'open_http_port': 15,
            'http_to_https_redirect_missing': 18,

            # Info findings (0-9 points)
            'service_banner_disclosed': 5,
            'technology_stack_identified': 3,
        }

    def calculate_risk_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate comprehensive risk score (0-100).

        Args:
            finding: Dictionary containing finding details
                Required keys:
                - finding_type: Type of finding
                - affected_asset: Asset identifier (domain/subdomain/IP)
                Optional keys:
                - port: Port number for network findings
                - status: active/inactive
                - context: Additional context data

        Returns:
            Integer risk score between 0 and 100
        """
        base_score = self._calculate_base_score(finding)
        context_score = self._calculate_context_score(finding)
        exposure_score = self._calculate_exposure_score(finding)

        # Calculate weighted total
        total = (
            base_score * (self.base_weight / 0.4) +
            context_score * (self.context_weight / 0.4) +
            exposure_score * (self.exposure_weight / 0.2)
        )

        # Normalize to 0-100 range
        normalized = int(total)
        return min(100, max(0, normalized))

    def _calculate_base_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate base risk score (0-40 points).

        Base score represents the inherent risk of the finding type,
        independent of context or exposure.

        Uses centralized KEYWORD_RISK_SCORES from constants for consistency.

        Args:
            finding: Finding dictionary

        Returns:
            Base score (0-40)
        """
        finding_type = finding.get('finding_type', 'unknown')

        # Check if we have a predefined score
        if finding_type in self.base_risk_map:
            return self.base_risk_map[finding_type]

        # Dynamic scoring based on keywords using centralized scores
        # Default moderate risk (20 points base score, not threshold)
        score = 20

        finding_lower = finding_type.lower()

        # Check for keywords in finding type and use highest matching score
        for keyword, keyword_score in KEYWORD_RISK_SCORES.items():
            if keyword in finding_lower:
                score = max(score, keyword_score)

        return min(40, score)

    def _calculate_context_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate context score (0-40 points).

        Context score considers business-critical factors:
        - Asset criticality (production, API, staging)
        - Service sensitivity (databases, auth services)
        - Data classification implications

        Args:
            finding: Finding dictionary

        Returns:
            Context score (0-40)
        """
        score = 0
        affected_asset = finding.get('affected_asset', '').lower()
        port = finding.get('port')

        # Production/critical asset indicators (+20 points)
        production_keywords = ['prod', 'production', 'api', 'www', 'app', 'portal']
        if any(keyword in affected_asset for keyword in production_keywords):
            score += 20

        # Staging/dev assets get lower score (+5 points)
        elif any(keyword in affected_asset for keyword in ['staging', 'stage', 'dev', 'test']):
            score += 5

        # Database ports (+15 points)
        database_ports = self.config.get('analysis.detectors.port_detector.database_ports', [3306, 5432, 27017, 6379])
        if port and port in database_ports:
            score += 15

        # Authentication service ports (+15 points)
        auth_ports = self.config.get('analysis.detectors.port_detector.auth_ports', [389, 636, 88, 464])
        if port and port in auth_ports:
            score += 15

        # Admin/management interfaces (+10 points)
        if any(keyword in affected_asset for keyword in ['admin', 'manage', 'cpanel', 'phpmyadmin']):
            score += 10

        return min(40, score)

    def _calculate_exposure_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate exposure score (0-20 points).

        Exposure score considers:
        - Public accessibility
        - Active service status
        - Response to probes

        Args:
            finding: Finding dictionary

        Returns:
            Exposure score (0-20)
        """
        score = 0

        # Check if asset is publicly accessible
        affected_asset = finding.get('affected_asset', '')
        if self._is_publicly_accessible(affected_asset):
            score += 15

        # Active/responsive service (+5 points)
        # Check both standard status enum values and common status strings
        status = finding.get('status', '').lower()
        active_statuses = [
            FindingStatus.OPEN.value,
            'active',
            'up',
            'responsive',
            'online'
        ]
        if status in active_statuses:
            score += 5

        # Has open port or responding service
        if finding.get('port') or finding.get('response_code'):
            score += 5

        return min(20, score)

    def _is_publicly_accessible(self, asset: str) -> bool:
        """
        Determine if an asset is likely publicly accessible.

        Args:
            asset: Asset identifier (domain/subdomain/IP)

        Returns:
            True if likely public, False otherwise
        """
        # Private network indicators
        private_indicators = [
            'localhost',
            '127.0.0.1',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '192.168.',
            '.local',
            '.internal',
            '.corp'
        ]

        asset_lower = asset.lower()
        return not any(indicator in asset_lower for indicator in private_indicators)

    def map_score_to_severity(self, score: int) -> str:
        """
        Map numeric risk score to severity label.

        Uses configurable thresholds from config (with RiskThresholds as defaults).
        Returns Severity enum values for consistency.

        Args:
            score: Risk score (0-100)

        Returns:
            Severity label: critical/high/medium/low/info
        """
        # Use configurable thresholds with RiskThresholds as fallback defaults
        if score >= self.thresholds.get('critical', RiskThresholds.CRITICAL_MIN):
            return Severity.CRITICAL.value
        elif score >= self.thresholds.get('high', RiskThresholds.HIGH_MIN):
            return Severity.HIGH.value
        elif score >= self.thresholds.get('medium', RiskThresholds.MEDIUM_MIN):
            return Severity.MEDIUM.value
        elif score >= self.thresholds.get('low', RiskThresholds.LOW_MIN):
            return Severity.LOW.value
        else:
            return Severity.INFO.value

    def score_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a finding and return enhanced finding with risk data.

        Args:
            finding: Finding dictionary

        Returns:
            Finding dictionary enhanced with:
            - risk_score: Numeric score (0-100)
            - severity: Severity label
            - score_breakdown: Component scores for transparency
        """
        risk_score = self.calculate_risk_score(finding)

        # Override score if severity_hint is critical to ensure it meets the threshold
        if (finding.get('severity_hint') == Severity.CRITICAL.value and
            risk_score < self.thresholds.get('critical', RiskThresholds.CRITICAL_MIN)):
            risk_score = self.thresholds.get('critical', RiskThresholds.CRITICAL_MIN)

        severity = self.map_score_to_severity(risk_score)

        # Add scoring details to finding
        finding_with_score = finding.copy()
        finding_with_score['risk_score'] = risk_score
        finding_with_score['severity'] = severity
        finding_with_score['score_breakdown'] = {
            'base_score': self._calculate_base_score(finding),
            'context_score': self._calculate_context_score(finding),
            'exposure_score': self._calculate_exposure_score(finding),
            'total': risk_score
        }

        return finding_with_score

    def get_confidence_level(self, finding: Dict[str, Any]) -> str:
        """
        Determine confidence level of the finding.

        Args:
            finding: Finding dictionary

        Returns:
            Confidence level: high/medium/low
        """
        # Confidence based on finding type and evidence
        finding_type = finding.get('finding_type', '')
        has_evidence = bool(finding.get('evidence'))
        has_verification = bool(finding.get('verified', False))

        # High confidence: verified findings with evidence
        if has_verification and has_evidence:
            return 'high'

        # Medium confidence: has evidence or known pattern
        if has_evidence or finding_type in self.base_risk_map:
            return 'medium'

        # Low confidence: inferential findings
        return 'low'
