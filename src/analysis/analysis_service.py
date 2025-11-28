"""
Analysis Service for OpenEASD Analysis Layer.

Orchestrates vulnerability detection, risk scoring, and finding management.
This service coordinates all detectors and integrates with the database layer.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.analysis.config import get_analysis_config
from src.analysis.scoring.risk_scorer import RiskScorer
from src.analysis.detectors.port_detector import PortVulnerabilityDetector
from src.utils.timezone import get_ist_now


logger = logging.getLogger(__name__)


class AnalysisService:
    """
    Orchestrates the analysis workflow for scan results.

    Workflow:
    1. Load enabled detectors
    2. Run detectors on scan data
    3. Score findings with risk scorer
    4. Deduplicate findings
    5. Store findings in database
    6. Generate statistics
    """

    def __init__(self, db_manager=None, event_publisher=None):
        """
        Initialize analysis service.

        Args:
            db_manager: Database manager instance (optional, for testing)
            event_publisher: Optional EventPublisher for real-time event broadcasting
        """
        self.config = get_analysis_config()
        self.db_manager = db_manager
        self.publisher = event_publisher

        # Initialize risk scorer
        self.risk_scorer = RiskScorer()

        # Initialize detectors
        self.detectors = self._load_detectors()

        logger.info(f"AnalysisService initialized with {len(self.detectors)} detectors")

    def _load_detectors(self) -> List[Any]:
        """
        Load and initialize all enabled detectors.

        Returns:
            List of enabled detector instances
        """
        detectors = []

        # Port Detector
        if self.config.get('analysis.detectors.port_detector.enabled', True):
            port_config = self.config.get('analysis.detectors.port_detector', {})
            detectors.append(PortVulnerabilityDetector(config=port_config))
            logger.info("Loaded PortVulnerabilityDetector")

        # TODO: Add more detectors as they are implemented
        # - WebVulnerabilityDetector
        # - TLSVulnerabilityDetector
        # - DNSVulnerabilityDetector
        # - EmailSecurityDetector

        return detectors

    async def analyze_scan_results(
        self,
        scan_id: str,
        scan_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze scan results and generate findings.

        This is the main entry point for analysis. It orchestrates:
        1. Running all enabled detectors
        2. Scoring findings
        3. Deduplicating findings
        4. Storing in database

        Args:
            scan_id: UUID of the scan session
            scan_data: Dictionary containing scan results:
                - subfinder_results: List of subdomain dictionaries
                - dnsx_results: List of DNS resolution dictionaries
                - naabu_results: List of open port dictionaries
                - httpx_results: List of HTTP probe dictionaries (future)

        Returns:
            Dictionary containing analysis results:
            {
                'scan_id': str,
                'findings_count': int,
                'findings': List[Dict],
                'statistics': Dict,
                'analysis_timestamp': str
            }
        """
        logger.info(f"Starting analysis for scan_id: {scan_id}")

        # Publish analysis started event
        if self.publisher:
            self.publisher.publish_analysis_started(
                scan_id=scan_id,
                detector_count=len(self.detectors)
            )

        analysis_start_time = time.time()

        try:
            # Step 1: Collect findings from all detectors
            all_findings = []
            detector_stats = {}

            for detector in self.detectors:
                if not detector.is_enabled():
                    continue

                try:
                    detector_name = detector.get_name()
                    logger.debug(f"Running detector: {detector_name}")

                    findings = detector.analyze(scan_data)
                    all_findings.extend(findings)

                    detector_stats[detector_name] = {
                        'findings_count': len(findings),
                        'status': 'success'
                    }

                    logger.info(f"{detector_name} found {len(findings)} findings")

                except Exception as e:
                    detector_name = detector.get_name()
                    logger.error(f"Error in {detector_name}: {e}", exc_info=True)
                    detector_stats[detector_name] = {
                        'findings_count': 0,
                        'status': 'error',
                        'error': str(e)
                    }

            logger.info(f"Collected {len(all_findings)} total findings from {len(self.detectors)} detectors")

            # Step 2: Score findings
            scored_findings = []
            for finding in all_findings:
                try:
                    scored_finding = self.risk_scorer.score_finding(finding)
                    scored_findings.append(scored_finding)
                except Exception as e:
                    logger.error(f"Error scoring finding: {e}", exc_info=True)
                    # Include unscored finding with default values
                    finding['risk_score'] = 50
                    finding['severity'] = 'medium'
                    scored_findings.append(finding)

            logger.info(f"Scored {len(scored_findings)} findings")

            # Step 3: Deduplicate findings
            deduplicated_findings = self._deduplicate_findings(scored_findings)
            logger.info(f"After deduplication: {len(deduplicated_findings)} unique findings")

            # Step 4: Add scan metadata to findings
            analysis_timestamp = get_ist_now()
            for finding in deduplicated_findings:
                finding['scan_id'] = scan_id
                finding['analysis_timestamp'] = analysis_timestamp.isoformat()

            # Step 5: Store findings in database (if db_manager available)
            if self.db_manager:
                try:
                    await self._store_findings(scan_id, deduplicated_findings)
                    logger.info(f"Stored {len(deduplicated_findings)} findings in database")
                except Exception as e:
                    logger.error(f"Error storing findings: {e}", exc_info=True)

            # Step 6: Publish finding discovered events
            if self.publisher:
                for finding in deduplicated_findings:
                    # Generate finding ID if not present
                    finding_id = finding.get('finding_id', f"{scan_id}_{finding.get('finding_type', 'unknown')}_{finding.get('affected_asset', 'unknown')}")

                    self.publisher.publish_finding_discovered(
                        scan_id=scan_id,
                        finding_id=finding_id,
                        finding_type=finding.get('finding_type', 'unknown'),
                        severity=finding.get('severity', 'info'),
                        affected_asset=finding.get('affected_asset', 'unknown'),
                        risk_score=finding.get('risk_score', 0),
                        port=finding.get('port'),
                        protocol=finding.get('protocol'),
                        title=finding.get('title')
                    )

            # Step 7: Generate statistics
            statistics = self._generate_statistics(deduplicated_findings, detector_stats)

            # Calculate analysis duration
            analysis_duration = time.time() - analysis_start_time

            # Publish analysis completed event
            if self.publisher:
                detector_names = [d.get_name() for d in self.detectors if d.is_enabled()]
                self.publisher.publish_analysis_completed(
                    scan_id=scan_id,
                    findings_count=len(deduplicated_findings),
                    duration_seconds=analysis_duration,
                    detectors_run=detector_names
                )

            return {
                'scan_id': scan_id,
                'findings_count': len(deduplicated_findings),
                'findings': deduplicated_findings,
                'statistics': statistics,
                'analysis_timestamp': analysis_timestamp.isoformat()
            }

        except Exception as e:
            logger.error(f"Analysis failed for scan_id {scan_id}: {e}", exc_info=True)

            # Publish analysis failed event
            if self.publisher:
                self.publisher.publish_analysis_failed(
                    scan_id=scan_id,
                    error=str(e)
                )

            raise

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings based on key attributes.

        Deduplication strategy:
        - Group by: finding_type + affected_asset + port (if applicable)
        - Keep highest severity finding from each group

        Args:
            findings: List of finding dictionaries

        Returns:
            Deduplicated list of findings
        """
        if not findings:
            return []

        # Create deduplication key
        seen_keys = {}

        for finding in findings:
            # Build deduplication key
            key_parts = [
                finding.get('finding_type', 'unknown'),
                finding.get('affected_asset', 'unknown'),
            ]

            # Add port if present (for network findings)
            if 'port' in finding:
                key_parts.append(str(finding['port']))

            dedup_key = '|'.join(key_parts)

            # Keep finding with higher risk score
            if dedup_key not in seen_keys:
                seen_keys[dedup_key] = finding
            else:
                existing_score = seen_keys[dedup_key].get('risk_score', 0)
                new_score = finding.get('risk_score', 0)

                if new_score > existing_score:
                    seen_keys[dedup_key] = finding

        deduplicated = list(seen_keys.values())

        # Sort by risk score (highest first)
        deduplicated.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

        return deduplicated

    async def _store_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        """
        Store findings in database.

        Args:
            scan_id: Scan session UUID
            findings: List of finding dictionaries
        """
        if not self.db_manager:
            logger.warning("No database manager available, skipping storage")
            return

        try:
            # Ensure each finding has an ID
            for finding in findings:
                if 'id' not in finding:
                    import uuid
                    finding['id'] = str(uuid.uuid4())

            # Store findings using SQLModelManager
            self.db_manager.store_findings(findings)
            logger.info(f"Successfully stored {len(findings)} findings for scan_id: {scan_id}")

        except Exception as e:
            logger.error(f"Failed to store findings: {e}", exc_info=True)
            raise

    def _generate_statistics(
        self,
        findings: List[Dict[str, Any]],
        detector_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate analysis statistics.

        Args:
            findings: List of findings
            detector_stats: Per-detector statistics

        Returns:
            Statistics dictionary
        """
        if not findings:
            return {
                'total_findings': 0,
                'by_severity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                },
                'by_detector': detector_stats,
                'highest_risk_score': 0,
                'average_risk_score': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'info_findings': 0
            }

        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate risk score statistics
        risk_scores = [f.get('risk_score', 0) for f in findings]
        highest_score = max(risk_scores) if risk_scores else 0
        average_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        return {
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'by_detector': detector_stats,
            'highest_risk_score': highest_score,
            'average_risk_score': round(average_score, 2),
            'critical_findings': severity_counts.get('critical', 0),
            'high_findings': severity_counts.get('high', 0),
            'medium_findings': severity_counts.get('medium', 0),
            'low_findings': severity_counts.get('low', 0),
            'info_findings': severity_counts.get('info', 0)
        }

    async def get_scan_findings(
        self,
        scan_id: str,
        min_severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve findings for a specific scan.

        Args:
            scan_id: Scan session UUID
            min_severity: Minimum severity filter (critical/high/medium/low/info)

        Returns:
            List of finding dictionaries
        """
        if not self.db_manager:
            logger.warning("No database manager available")
            return []

        try:
            result = self.db_manager.get_findings(
                scan_id=scan_id,
                min_severity=min_severity
            )
            return result.get('findings', [])

        except Exception as e:
            logger.error(f"Failed to retrieve findings for scan {scan_id}: {e}", exc_info=True)
            return []

    async def get_findings_by_asset(
        self,
        asset: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve findings for a specific asset (domain/subdomain/IP).

        Args:
            asset: Asset identifier
            limit: Maximum number of findings to return

        Returns:
            List of finding dictionaries
        """
        if not self.db_manager:
            logger.warning("No database manager available")
            return []

        try:
            result = self.db_manager.get_findings(
                affected_asset=asset,
                limit=limit
            )
            return result.get('findings', [])

        except Exception as e:
            logger.error(f"Failed to retrieve findings for asset {asset}: {e}", exc_info=True)
            return []

    def is_enabled(self) -> bool:
        """Check if analysis layer is enabled."""
        return self.config.is_enabled()

    def is_auto_analyze_enabled(self) -> bool:
        """Check if auto-analysis on scan completion is enabled."""
        return self.config.is_auto_analyze_enabled()

    def get_detector_count(self) -> int:
        """Get count of loaded detectors."""
        return len(self.detectors)

    def get_detector_names(self) -> List[str]:
        """Get names of all loaded detectors."""
        return [d.get_name() for d in self.detectors]
