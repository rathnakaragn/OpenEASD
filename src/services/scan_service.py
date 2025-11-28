"""
Scan management service.

Handles business logic for scan operations including
creation, execution, status tracking, and results retrieval.
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain, is_private_ip
from src.tools.runners import run_subfinder, run_naabu, run_dnsx, run_httpx
from src.utils.timezone import get_ist_now
from src.analysis.analysis_service import AnalysisService
from src.messaging.publisher import EventPublisher

logger = logging.getLogger(__name__)


def is_web_service(httpx_result: Dict[str, Any]) -> tuple[bool, float]:
    """
    Determine if httpx result indicates a web service.

    Args:
        httpx_result: Result from httpx probe containing status_code, server, title, etc.

    Returns:
        (is_web_service: bool, confidence: float 0.0-1.0)
    """
    status_code = httpx_result.get('status_code', 0)
    server = httpx_result.get('server', '')
    title = httpx_result.get('title', '')

    # HTTP 200-299 = definite web service
    if 200 <= status_code < 300:
        return True, 0.95

    # Server header present = likely web service
    if server:
        return True, 0.85

    # HTTP 4xx/5xx = broken web service
    if 400 <= status_code < 600:
        return True, 0.60

    # No response = not a web service
    return False, 0.90


class ScanService:
    """Service for managing scans."""

    def __init__(
        self,
        db_manager: SQLModelManager,
        enable_analysis: bool = True,
        event_publisher: Optional[EventPublisher] = None
    ):
        """
        Initialize scan service.

        Args:
            db_manager: Database manager instance
            enable_analysis: Enable analysis layer integration (default: True)
            event_publisher: Optional EventPublisher for real-time event broadcasting
        """
        self.db = db_manager
        self.publisher = event_publisher  # NEW: Event publisher for messaging layer

        # Initialize analysis service if enabled
        self.analysis_service = None
        if enable_analysis:
            try:
                self.analysis_service = AnalysisService(
                    db_manager=db_manager,
                    event_publisher=event_publisher  # Pass publisher to analysis layer
                )
                if self.analysis_service.is_enabled():
                    logger.info("Analysis Layer enabled for scan service")
                else:
                    logger.info("Analysis Layer disabled in configuration")
                    self.analysis_service = None
            except Exception as e:
                logger.warning(f"Failed to initialize Analysis Layer: {e}")
                self.analysis_service = None

    def _format_datetime(self, dt: Optional[Union[datetime, str]]) -> str:
        """
        Convert datetime object to ISO format string.

        Args:
            dt: Datetime object or string

        Returns:
            ISO format datetime string
        """
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt) if dt else ''

    def _run_analysis_safely(self, scan_id: str, scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run analysis safely, handling async context properly.

        Args:
            scan_id: Scan ID for analysis
            scan_data: Scan data to analyze

        Returns:
            Analysis results dictionary, or None if analysis fails
        """
        try:
            # Try to get existing event loop
            try:
                loop = asyncio.get_running_loop()
                # If we're already in an async context, we can't use asyncio.run()
                logger.warning("Already in async context, skipping analysis")
                return None
            except RuntimeError:
                # No event loop running, safe to use asyncio.run()
                return asyncio.run(
                    self.analysis_service.analyze_scan_results(scan_id, scan_data)
                )
        except Exception as e:
            logger.error(f"Error running analysis: {e}", exc_info=True)
            return None

    def create_scan(
        self,
        domains: List[str],
        scan_type: str = 'passive_subdomain_enum',
        tool_name: str = 'subfinder'
    ) -> Dict[str, Any]:
        """
        Create a new scan session.

        Args:
            domains: List of domains to scan
            scan_type: Type of scan to perform
            tool_name: Tool to use for scanning

        Returns:
            Dictionary containing scan session ID and metadata
        """
        # Validate all domains
        validated_domains = [validate_domain(d) for d in domains]

        # Create scan session
        scan_id = self.db.create_scan_session(
            scan_type=scan_type,
            domains=validated_domains,
            tool_name=tool_name
        )

        return {
            'success': True,
            'scan_id': scan_id,
            'domains': validated_domains,
            'scan_type': scan_type,
            'tool_name': tool_name
        }

    def execute_scan(
        self,
        domain: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a complete scan workflow for a domain.

        Args:
            domain: Domain to scan
            timeout: Optional timeout in seconds

        Returns:
            Dictionary containing scan results
        """
        # Validate domain
        domain = validate_domain(domain)

        # Create scan session
        scan_id = self.db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=[domain],
            tool_name='subfinder'
        )

        # Publish scan started event
        if self.publisher:
            self.publisher.publish_scan_started(
                scan_id=scan_id,
                domain=domain,
                scan_type='passive_subdomain_enum',
                tool_name='subfinder'
            )

        try:
            # Step 1: Subdomain discovery (subfinder)
            # Publish tool started event
            if self.publisher:
                self.publisher.publish_tool_started(
                    scan_id=scan_id,
                    tool_name='subfinder',
                    domain=domain
                )

            subfinder_start = time.time()
            subdomains = run_subfinder(domain, timeout=timeout)
            subfinder_duration = time.time() - subfinder_start

            # Publish tool completed event
            if self.publisher:
                self.publisher.publish_tool_completed(
                    scan_id=scan_id,
                    tool_name='subfinder',
                    domain=domain,
                    results_count=len(subdomains),
                    duration_seconds=subfinder_duration
                )

            # Store subfinder results in database
            if subdomains:
                subfinder_results_for_db = []
                for subdomain in subdomains:
                    subfinder_results_for_db.append({
                        'scan_id': scan_id,
                        'apex_domain': domain,
                        'subdomain': subdomain,
                        'discovered_at': get_ist_now()
                    })
                self.db.store_subfinder_results(subfinder_results_for_db)

            # Step 2: DNS resolution (dnsx)
            active_subdomains = []
            if subdomains:
                # Publish tool started event
                if self.publisher:
                    self.publisher.publish_tool_started(
                        scan_id=scan_id,
                        tool_name='dnsx',
                        domain=domain,
                        target_count=len(subdomains)
                    )

                dnsx_start = time.time()
                dns_results = run_dnsx(subdomains, record_types=['a'], timeout=timeout)
                dnsx_duration = time.time() - dnsx_start

                # Filter for public IPs only (skip private/reserved IP ranges)
                active_subdomains = [
                    r['host'] for r in dns_results
                    if r.get('a') and not is_private_ip(r['a'][0])
                ]

                # Publish tool completed event
                if self.publisher:
                    self.publisher.publish_tool_completed(
                        scan_id=scan_id,
                        tool_name='dnsx',
                        domain=domain,
                        results_count=len(active_subdomains),
                        duration_seconds=dnsx_duration
                    )

            # Step 3: Port scanning (naabu)
            ports_found = []
            if active_subdomains:
                # Publish tool started event
                if self.publisher:
                    self.publisher.publish_tool_started(
                        scan_id=scan_id,
                        tool_name='naabu',
                        domain=domain,
                        target_count=len(active_subdomains)
                    )

                naabu_start = time.time()
                ports_found = run_naabu(active_subdomains, timeout=timeout)
                naabu_duration = time.time() - naabu_start

                # Publish tool completed event
                if self.publisher:
                    self.publisher.publish_tool_completed(
                        scan_id=scan_id,
                        tool_name='naabu',
                        domain=domain,
                        results_count=len(ports_found),
                        duration_seconds=naabu_duration
                    )

                # Store naabu results in database
                if ports_found:
                    naabu_results_for_db = []
                    for port_info in ports_found:
                        naabu_results_for_db.append({
                            'scan_id': scan_id,
                            'target_host': port_info.get('host', ''),
                            'port': port_info.get('port'),
                            'protocol': port_info.get('protocol', 'tcp'),
                            'ip': port_info.get('ip', ''),
                            'discovered_at': get_ist_now()
                        })
                    self.db.store_naabu_results(naabu_results_for_db)

            # Add domain if it doesn't exist
            if not self.db.domain_exists(domain):
                self.db.add_domain(domain, is_primary=True)

            # Generate alerts
            alerts = []

            # Alert for new subdomains
            for subdomain in subdomains:
                alerts.append({
                    'scan_id': scan_id,
                    'domain': subdomain,
                    'vulnerability_type': 'subdomain_discovered',
                    'severity': 'info',
                    'description': f'Subdomain discovered: {subdomain}',
                    'tool_source': 'subfinder',
                    'discovered_at': get_ist_now()
                })

            # Step 4: Probe open ports for web services
            httpx_targets = []
            for port_info in ports_found:
                host = port_info.get('host', '')
                port = port_info.get('port')
                # Determine scheme based on port
                scheme = 'https' if port in [443, 8443] else 'http'
                target = f"{scheme}://{host}:{port}"
                httpx_targets.append((target, port_info))

            # Run httpx probes
            httpx_results = {}
            if httpx_targets:
                try:
                    # Publish tool started event
                    if self.publisher:
                        self.publisher.publish_tool_started(
                            scan_id=scan_id,
                            tool_name='httpx',
                            domain=domain,
                            target_count=len(httpx_targets)
                        )

                    httpx_start = time.time()
                    target_urls = [t[0] for t in httpx_targets]
                    httpx_data = run_httpx(target_urls, timeout=timeout)
                    httpx_duration = time.time() - httpx_start

                    # Map results back to port_info
                    for httpx_result in httpx_data:
                        httpx_results[httpx_result.get('url')] = httpx_result

                    # Publish tool completed event
                    if self.publisher:
                        self.publisher.publish_tool_completed(
                            scan_id=scan_id,
                            tool_name='httpx',
                            domain=domain,
                            results_count=len(httpx_data),
                            duration_seconds=httpx_duration
                        )

                    logger.info(f"Probed {len(httpx_targets)} ports for web services")
                except Exception as e:
                    logger.warning(f"httpx probe failed: {e}")
                    # Publish tool failed event
                    if self.publisher:
                        self.publisher.publish_tool_failed(
                            scan_id=scan_id,
                            tool_name='httpx',
                            domain=domain,
                            error=str(e)
                        )

            # Alert for open ports (separated by web service status)
            for target_url, port_info in httpx_targets:
                httpx_result = httpx_results.get(target_url)

                if httpx_result:
                    # Check if it's a web service
                    is_web, confidence = is_web_service(httpx_result)

                    if is_web:
                        # Alert for web service
                        alert = {
                            'scan_id': scan_id,
                            'domain': port_info.get('host', ''),
                            'vulnerability_type': 'web_service_detected',
                            'severity': 'low',  # Lower severity - expected
                            'description': f"Web service found on port {port_info.get('port')} - {httpx_result.get('server', 'Unknown')}",
                            'tool_source': 'httpx',
                            'discovered_at': get_ist_now()
                        }
                        alerts.append(alert)
                    else:
                        # Alert for non-web service (suspicious!)
                        alert = {
                            'scan_id': scan_id,
                            'domain': port_info.get('host', ''),
                            'vulnerability_type': 'non_web_service_port',
                            'severity': 'medium',  # Higher severity - unexpected
                            'description': f"Non-web service port open: {port_info.get('port')} ({port_info.get('protocol', 'tcp')})",
                            'tool_source': 'naabu+httpx',
                            'discovered_at': get_ist_now()
                        }
                        alerts.append(alert)
                else:
                    # No httpx result means port didn't respond to HTTP - it's a non-web service (suspicious!)
                    alert = {
                        'scan_id': scan_id,
                        'domain': port_info.get('host', ''),
                        'vulnerability_type': 'non_web_service_port',
                        'severity': 'medium',  # Higher severity - unexpected service
                        'description': f"Non-web service port open: {port_info.get('port')} ({port_info.get('protocol', 'tcp')})",
                        'tool_source': 'naabu+httpx',
                        'discovered_at': get_ist_now()
                    }
                    alerts.append(alert)

            # Store alerts
            if alerts:
                self.db.store_alerts(alerts)

            # Run analysis if enabled
            analysis_results = None
            if self.analysis_service and self.analysis_service.is_auto_analyze_enabled():
                logger.info(f"Running analysis for scan {scan_id}")

                # Prepare scan data for analysis
                scan_data = {
                    'scan_id': scan_id,
                    'domain': domain,
                    'subfinder_results': [{'subdomain': s} for s in subdomains],
                    'dnsx_results': dns_results if 'dns_results' in locals() else [],
                    'naabu_results': ports_found
                }

                # Run analysis safely (handles async context)
                analysis_results = self._run_analysis_safely(scan_id, scan_data)

                if analysis_results:
                    logger.info(f"Analysis completed: {analysis_results.get('findings_count', 0)} findings")
                else:
                    logger.debug(f"Analysis skipped or failed for scan {scan_id}")

            # Update scan status
            findings_count = len(alerts)
            if analysis_results:
                findings_count += analysis_results.get('findings_count', 0)

            self.db.update_scan_status(
                scan_id,
                'completed',
                end_time=get_ist_now(),
                findings_count=findings_count
            )

            # Publish scan completed event
            if self.publisher:
                # Calculate total duration from scan start
                scan_start_time = self.db.get_scan_session(scan_id).get('start_time')
                if scan_start_time:
                    from datetime import datetime
                    scan_duration = (get_ist_now() - scan_start_time).total_seconds()
                else:
                    scan_duration = 0.0

                # Collect all tools executed
                tools_executed = ['subfinder']
                if subdomains:
                    tools_executed.append('dnsx')
                if active_subdomains:
                    tools_executed.append('naabu')
                if httpx_targets:
                    tools_executed.append('httpx')

                self.publisher.publish_scan_completed(
                    scan_id=scan_id,
                    domain=domain,
                    findings_count=findings_count,
                    duration_seconds=scan_duration,
                    tools_executed=tools_executed
                )

            result = {
                'success': True,
                'scan_id': scan_id,
                'domain': domain,
                'subdomains': subdomains,
                'subdomain_count': len(subdomains),
                'active_subdomains': active_subdomains,
                'active_count': len(active_subdomains),
                'ports_found': ports_found,
                'ports_count': len(ports_found),
                'alerts_count': len(alerts)
            }

            # Add analysis results if available
            if analysis_results:
                result['analysis'] = {
                    'findings_count': analysis_results.get('findings_count', 0),
                    'statistics': analysis_results.get('statistics', {})
                }

            return result

        except Exception as e:
            # Update scan status to failed
            self.db.update_scan_status(
                scan_id,
                'failed',
                end_time=get_ist_now()
            )

            # Publish scan failed event
            if self.publisher:
                self.publisher.publish_scan_failed(
                    scan_id=scan_id,
                    domain=domain,
                    error=str(e)
                )

            raise

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get status of a scan session.

        Args:
            scan_id: Scan session ID

        Returns:
            Dictionary containing scan status information

        Raises:
            ValueError: If scan ID doesn't exist
        """
        scan_info = self.db.get_scan_status(scan_id)

        if not scan_info:
            raise ValueError(f'Scan ID not found: {scan_id}')

        return {
            'success': True,
            'scan': scan_info
        }

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get results for a scan session.

        Args:
            scan_id: Scan session ID

        Returns:
            Dictionary containing scan results

        Raises:
            ValueError: If scan ID doesn't exist
        """
        # Get scan info
        scan_info = self.db.get_scan_status(scan_id)

        if not scan_info:
            raise ValueError(f'Scan ID not found: {scan_id}')

        # Get subfinder results (subdomains)
        subfinder_results = self.db.get_tool_results(
            scan_id=scan_id,
            tool_name='subfinder',
            limit=10000
        )

        subdomains = []
        for result in subfinder_results.get('results', []):
            subdomains.append({
                'subdomain': result.get('subdomain', ''),
                'ip_address': result.get('ip_address', ''),
                'discovered_at': self._format_datetime(result.get('discovered_at'))
            })

        # Get naabu results (ports)
        naabu_results = self.db.get_tool_results(
            scan_id=scan_id,
            tool_name='naabu',
            limit=10000
        )

        ports = []
        for result in naabu_results.get('results', []):
            ports.append({
                'subdomain': result.get('target_host', ''),
                'port': result.get('port', 0),
                'protocol': result.get('protocol', 'tcp'),
                'ip': result.get('ip', ''),
                'discovered_at': self._format_datetime(result.get('discovered_at'))
            })

        # Extract domains from scan info
        domains_scanned = scan_info.get('domains_scanned', [])
        first_domain = domains_scanned[0] if domains_scanned else ''

        return {
            'success': True,
            'scan': {
                'scan_id': scan_info['scan_id'],
                'domain': first_domain,
                'scan_type': scan_info.get('scan_type', 'passive_subdomain_enum'),
                'tool_name': scan_info.get('tool_name', 'subfinder'),
                'status': scan_info['status'],
                'start_time': self._format_datetime(scan_info.get('start_time')),
                'end_time': self._format_datetime(scan_info.get('end_time')),
                'findings_count': scan_info.get('findings_count', 0),
                'total_subdomains': len(subdomains),
                'total_ports': len(ports)
            },
            'subdomains': subdomains,
            'ports': ports
        }

    def list_scans(self, limit: int = 20) -> Dict[str, Any]:
        """
        List scan sessions.

        Args:
            limit: Maximum number of scans to return

        Returns:
            Dictionary containing list of scans
        """
        # Use database manager method instead of raw SQL
        result = self.db.get_scan_history(limit=limit)

        scans = []
        for scan in result.get('scans', []):
            # Extract first domain from domains_scanned
            domains = scan.get('domains_scanned', [])
            domain = domains[0] if domains else 'N/A'

            scans.append({
                'scan_id': scan.get('scan_id'),
                'scan_type': scan.get('scan_type'),
                'tool_name': scan.get('tool_name'),
                'domain': domain,
                'status': scan.get('status'),
                'findings_count': scan.get('findings_count', 0),
                'start_time': scan.get('start_time', 'N/A'),
                'end_time': scan.get('end_time', 'N/A')
            })

        return {
            'success': True,
            'scans': scans,
            'total': result.get('total_count', len(scans))
        }

    def execute_scan_async(self, domain: str, timeout: Optional[int] = None, save: bool = True) -> Dict[str, Any]:
        """
        Execute scan asynchronously (non-blocking for API).

        Creates a scan session immediately and returns, allowing
        the scan to be executed in the background.

        Args:
            domain: Domain to scan
            timeout: Optional timeout in seconds
            save: Whether to save results to database

        Returns:
            Dictionary containing scan session information
        """
        # Create scan session
        scan_id = self.db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=[domain],
            tool_name='subfinder'
        )

        logger.info(f"Created async scan session {scan_id} for domain: {domain}")

        # Return scan info immediately (scan will run in background)
        # Note: Background execution would be handled by FastAPI BackgroundTasks
        # or a task queue like Celery in production

        return {
            'success': True,
            'scan': {
                'scan_id': scan_id,
                'domain': domain,
                'scan_type': 'passive_subdomain_enum',
                'tool_name': 'subfinder',
                'status': 'pending',
                'findings_count': 0
            }
        }

    def trigger_analysis(self, scan_id: str) -> Dict[str, Any]:
        """
        Trigger analysis on a completed scan.

        Args:
            scan_id: ID of the scan to analyze

        Returns:
            Dictionary containing analysis status

        Raises:
            ValueError: If scan not found or not completed
        """
        # Get scan status
        scan_data = self.get_scan_status(scan_id)

        if not scan_data.get('scan'):
            raise ValueError(f"Scan not found: {scan_id}")

        # Check if scan is completed
        status = scan_data['scan'].get('status')
        if status not in ['completed', 'finished']:
            raise ValueError(f"Scan must be completed before analysis. Current status: {status}")

        # Trigger analysis
        # Note: This would be executed in background in production
        logger.info(f"Analysis triggered for scan: {scan_id}")

        return {
            'success': True,
            'scan_id': scan_id,
            'status': 'analyzing'
        }
