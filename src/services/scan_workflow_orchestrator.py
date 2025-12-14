"""
Scan Workflow Orchestrator.

Handles the 8-step scan workflow execution, extracted from ScanService
to reduce complexity and improve maintainability.

Workflow Steps:
1. Subdomain discovery (subfinder)
2. DNS resolution (dnsx)
3. Port scanning (naabu)
4. HTTP probing (httpx)
5. TLS verification (tlsx)
6. Service detection (nmap -sV)
7. Vulnerability detection (nuclei + nmap NSE) - both mandatory for non-web ports
8. Analysis (risk scoring)
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain, is_private_ip
from src.utils.collections import deduplicate_strings, deduplicate_by_key
from src.utils.domain_helpers import extract_host_from_port_info, make_port_key
from src.tools.runners import (
    run_subfinder,
    run_naabu,
    run_dnsx,
    run_httpx,
    run_tlsx_parallel,
    run_nmap_service_detection_parallel,
    run_nmap_vuln_detection_parallel,
    run_nuclei_network,
)
from src.utils.timezone import get_ist_now
from src.analysis.analysis_service import AnalysisService
from src.analysis.config import get_analysis_config

logger = logging.getLogger(__name__)


def is_web_service(httpx_result: Dict[str, Any]) -> Tuple[bool, float]:
    """
    Determine if httpx result indicates a web service.

    Args:
        httpx_result: Result from httpx probe containing status_code, server, title, etc.

    Returns:
        (is_web_service: bool, confidence: float 0.0-1.0)
    """
    status_code = httpx_result.get('status_code', 0)
    server = httpx_result.get('server', '')

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


class ScanWorkflowOrchestrator:
    """
    Orchestrates the 8-step scan workflow.

    This class is responsible for executing scan workflows while
    ScanService handles CRUD operations for scans.
    """

    def __init__(
        self,
        db_manager: SQLModelManager,
        enable_analysis: bool = True
    ):
        """
        Initialize scan workflow orchestrator.

        Args:
            db_manager: Database manager instance
            enable_analysis: Enable analysis layer integration (default: True)
        """
        self.db = db_manager
        self._load_service_classifications()
        self._init_analysis_service(enable_analysis)

    def _load_service_classifications(self) -> None:
        """Load service classifications from config."""
        try:
            config = get_analysis_config()
            self.critical_services = config.get_critical_services()
            self.high_risk_services = config.get_high_risk_services()
            self.medium_risk_services = config.get_medium_risk_services()
            self.low_risk_services = config.get_low_risk_services()
            logger.debug("Loaded service classifications from config")
        except Exception as e:
            logger.warning(f"Failed to load service classifications from config: {e}")
            # Fallback to defaults
            self.critical_services = [
                'mysql', 'postgresql', 'mongodb', 'redis', 'memcached',
                'elasticsearch', 'cassandra', 'couchdb', 'mariadb', 'oracle', 'mssql'
            ]
            self.high_risk_services = [
                'telnet', 'ftp', 'rsh', 'rlogin', 'vnc', 'rdp', 'smb', 'netbios'
            ]
            self.medium_risk_services = [
                'ssh', 'smtp', 'dns', 'snmp', 'ldap', 'nfs', 'rpc'
            ]
            self.low_risk_services = ['ntp', 'ntp-time']

    def _init_analysis_service(self, enable_analysis: bool) -> None:
        """Initialize analysis service if enabled."""
        self.analysis_service = None
        if enable_analysis:
            try:
                self.analysis_service = AnalysisService(db_manager=self.db)
                if self.analysis_service.is_enabled():
                    logger.info("Analysis Layer enabled for scan workflow")
                else:
                    logger.info("Analysis Layer disabled in configuration")
                    self.analysis_service = None
            except Exception as e:
                logger.warning(f"Failed to initialize Analysis Layer: {e}")
                self.analysis_service = None

    # =========================================================================
    # Workflow Step Methods
    # =========================================================================

    def step1_discover_subdomains(
        self,
        domain: str,
        scan_id: str,
        timeout: Optional[int] = None
    ) -> List[str]:
        """
        Step 1: Discover subdomains using subfinder.

        Args:
            domain: Target domain
            scan_id: Scan session ID
            timeout: Optional timeout in seconds

        Returns:
            List of discovered subdomains (unique)
        """
        subdomains_raw = run_subfinder(domain, timeout=timeout)

        # Deduplicate subdomains (case-insensitive)
        subdomains = deduplicate_strings(subdomains_raw, case_insensitive=True)

        # Store unique results in database
        if subdomains:
            subfinder_results = [
                {
                    'scan_id': scan_id,
                    'apex_domain': domain,
                    'subdomain': subdomain,
                    'discovered_at': get_ist_now()
                }
                for subdomain in subdomains
            ]
            self.db.store_subfinder_results(subfinder_results)

        return subdomains

    def step2_resolve_dns(
        self,
        subdomains: List[str],
        timeout: Optional[int] = None
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """
        Step 2: Resolve DNS for subdomains and filter for public IPs.

        Args:
            subdomains: List of subdomains to resolve
            timeout: Optional timeout in seconds

        Returns:
            Tuple of (active_subdomains, dns_results)
        """
        if not subdomains:
            return [], []

        dns_results = run_dnsx(subdomains, record_types=['a'], timeout=timeout)

        # Filter for public IPs only
        active_subdomains = [
            r['host'] for r in dns_results
            if r.get('a') and not is_private_ip(r['a'][0])
        ]

        return active_subdomains, dns_results

    def step3_scan_ports(
        self,
        active_subdomains: List[str],
        scan_id: str,
        timeout: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Step 3: Scan ports on active subdomains using naabu.

        Args:
            active_subdomains: List of subdomains with public IPs
            scan_id: Scan session ID
            timeout: Optional timeout in seconds

        Returns:
            List of port information dictionaries (unique host:port combinations)
        """
        if not active_subdomains:
            return []

        ports_found_raw = run_naabu(active_subdomains, timeout=timeout)

        # Deduplicate by host:port (case-insensitive host)
        ports_found = deduplicate_by_key(
            ports_found_raw,
            key_func=lambda p: make_port_key(
                extract_host_from_port_info(p),
                p.get('port', 0)
            ),
            case_insensitive=True
        )

        # Store unique results in database
        if ports_found:
            naabu_results = [
                {
                    'scan_id': scan_id,
                    'target_host': port_info.get('subdomain', ''),
                    'port': port_info.get('port'),
                    'protocol': port_info.get('protocol', 'tcp'),
                    'ip': port_info.get('ip', ''),
                    'discovered_at': get_ist_now()
                }
                for port_info in ports_found
            ]
            self.db.store_naabu_results(naabu_results)

        return ports_found

    def step4_probe_http(
        self,
        ports_found: List[Dict[str, Any]],
        timeout: Optional[int] = None
    ) -> Tuple[List[Tuple], Dict[str, Any]]:
        """
        Step 4: Probe ports for HTTP/HTTPS services.

        Run before TLS verification to identify web services.
        Web services skip TLS verification since httpx already handles them.

        Args:
            ports_found: List of port information from naabu
            timeout: Optional timeout in seconds

        Returns:
            Tuple of (httpx_targets, httpx_results)
        """
        httpx_targets = []
        for port_info in ports_found:
            host = extract_host_from_port_info(port_info)
            port = port_info.get('port')
            scheme = 'https' if port in [443, 8443] else 'http'
            target = f"{scheme}://{host}:{port}"
            httpx_targets.append((target, port_info))

        if not httpx_targets:
            return [], {}

        try:
            target_urls = [t[0] for t in httpx_targets]
            httpx_data = run_httpx(target_urls, timeout=timeout)

            # Map results back to URLs
            httpx_results = {r.get('url'): r for r in httpx_data}
            logger.info(f"Probed {len(httpx_targets)} ports for web services")
            return httpx_targets, httpx_results
        except Exception as e:
            logger.warning(f"httpx probe failed: {e}")
            return httpx_targets, {}

    def step5_verify_tls(
        self,
        ports_found: List[Dict[str, Any]],
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Step 5: Verify TLS status on non-web service ports.

        Only called for ports that httpx identified as non-web services.
        Web services are already handled by httpx and don't need TLS verification.

        Args:
            ports_found: List of port information (non-web ports only)
            timeout: Optional timeout in seconds

        Returns:
            Dictionary of TLS verification results
        """
        if not ports_found:
            return {}

        # Ports to skip TLS check:
        # - Already encrypted ports (443, 8443, etc.)
        # - Web service ports (80, 8080, etc.) - handled by httpx, not tlsx
        skip_tls_check_ports = {
            # Encrypted ports (already have TLS)
            22, 443, 8443, 990, 993, 995, 636, 465,
            # Web service ports (HTTP - use httpx redirect detection instead)
            80, 8080, 8000, 8008, 8888, 3000, 5000, 9000
        }

        tlsx_targets = [
            (port_info.get('subdomain') or port_info.get('host') or '', port_info.get('port'))
            for port_info in ports_found
            if port_info.get('port') not in skip_tls_check_ports
            and (port_info.get('subdomain') or port_info.get('host'))
        ]

        if not tlsx_targets:
            logger.debug("No ports need TLS verification, skipping tlsx")
            return {}

        try:
            tlsx_results = run_tlsx_parallel(tlsx_targets, timeout=timeout)
            logger.info(f"tlsx completed: {len(tlsx_results)} results for {len(tlsx_targets)} ports")
            return tlsx_results
        except Exception as e:
            logger.warning(f"tlsx scan failed (non-fatal): {e}")
            return {}

    def step6_detect_services(
        self,
        non_web_ports: List[Tuple[str, int]]
    ) -> Dict[str, Any]:
        """
        Step 6: Detect services on non-web ports using nmap.

        Args:
            non_web_ports: List of (host, port) tuples

        Returns:
            Dictionary of service detection results
        """
        if not non_web_ports:
            return {}

        try:
            logger.info(f"Running parallel service detection for {len(non_web_ports)} non-web ports")
            nmap_results = run_nmap_service_detection_parallel(non_web_ports, max_workers=5)
            return nmap_results
        except Exception as e:
            logger.warning(f"Parallel service detection failed: {e}")
            return {}

    def step7_detect_vulnerabilities(
        self,
        nmap_service_results: Dict[str, Any],
        non_web_ports: List[Tuple[str, int]]
    ) -> Dict[str, Any]:
        """
        Step 7: Detect vulnerabilities using nuclei AND nmap NSE (both mandatory).

        Runs BOTH tools on all non-web ports for comprehensive coverage:
        - Nuclei: Fast, template-based scanning with network templates
        - Nmap NSE: Service-specific scripts for deep inspection

        Args:
            nmap_service_results: Results from service detection
            non_web_ports: List of (host, port) tuples for non-web services

        Returns:
            Dictionary of vulnerability detection results with structure:
            {
                'host:port': {
                    'nuclei': [...],      # Nuclei findings
                    'nmap': {...},        # Nmap NSE findings
                    'combined': [...]     # Merged findings
                }
            }
        """
        if not non_web_ports:
            return {}

        vuln_results = {}

        # Initialize results for all non-web ports
        for host, port in non_web_ports:
            port_key = f"{host}:{port}"
            vuln_results[port_key] = {
                'nuclei': [],
                'nmap': {'vulnerabilities': [], 'status': 'pending'},
                'combined': []
            }

        logger.info(f"Running vulnerability detection on {len(non_web_ports)} non-web ports")

        # Step 7a: Run nuclei network templates (MANDATORY)
        logger.info("Step 7a: Running nuclei network templates")
        nuclei_results = self._run_nuclei_scan(non_web_ports)

        # Step 7b: Run nmap NSE scripts (MANDATORY for all non-web ports)
        logger.info("Step 7b: Running nmap NSE scripts")
        nmap_results = self._run_nmap_nse_scan_all(non_web_ports, nmap_service_results)

        # Combine results
        for port_key in vuln_results:
            # Add nuclei findings
            if port_key in nuclei_results:
                vuln_results[port_key]['nuclei'] = nuclei_results[port_key]

            # Add nmap findings
            if port_key in nmap_results:
                vuln_results[port_key]['nmap'] = nmap_results[port_key]

            # Merge into combined list
            vuln_results[port_key]['combined'] = self._merge_vulnerability_findings(
                vuln_results[port_key]['nuclei'],
                vuln_results[port_key]['nmap']
            )

        total_findings = sum(len(v['combined']) for v in vuln_results.values())
        logger.info(f"Vulnerability detection complete: {total_findings} total findings")

        return vuln_results

    def _run_nuclei_scan(
        self,
        non_web_ports: List[Tuple[str, int]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run nuclei network templates on non-web ports.

        Args:
            non_web_ports: List of (host, port) tuples

        Returns:
            Dictionary mapping port_key to list of nuclei findings
        """
        if not non_web_ports:
            return {}

        targets = [f"{host}:{port}" for host, port in non_web_ports]

        try:
            logger.info(f"Running nuclei network scan on {len(targets)} non-web ports")
            findings = run_nuclei_network(targets, timeout=300)

            # Group findings by host:port
            results = {}
            for finding in findings:
                host = finding.get('host', '')
                if host:
                    if host not in results:
                        results[host] = []
                    results[host].append(finding)

            logger.info(f"Nuclei found {len(findings)} vulnerabilities")
            return results

        except Exception as e:
            logger.warning(f"Nuclei network scan failed (non-fatal): {e}")
            return {}

    def _run_nmap_nse_scan_all(
        self,
        non_web_ports: List[Tuple[str, int]],
        nmap_service_results: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Run nmap NSE scripts on ALL non-web ports (mandatory).

        For identified services: uses service-specific NSE scripts
        For unknown services: uses generic 'vuln' scripts

        Args:
            non_web_ports: List of (host, port) tuples for all non-web ports
            nmap_service_results: Results from service detection

        Returns:
            Dictionary mapping port_key to nmap vulnerability results
        """
        if not non_web_ports:
            return {}

        # Build list with service info (use 'unknown' for unidentified)
        ports_with_services = []
        for host, port in non_web_ports:
            port_key = f"{host}:{port}"
            service_result = nmap_service_results.get(port_key, {})

            if service_result.get('status') == 'success':
                service = service_result.get('service', 'unknown')
            else:
                service = 'unknown'

            # Skip web services - they're handled by nuclei web templates
            if service.lower() in ['http', 'https', 'http-proxy', 'http-alt']:
                continue

            ports_with_services.append((host, port, service))

        if not ports_with_services:
            return {}

        try:
            logger.info(f"Running nmap NSE scripts on {len(ports_with_services)} non-web ports")
            vuln_results = run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)
            return vuln_results
        except Exception as e:
            logger.warning(f"Nmap NSE scan failed (non-fatal): {e}")
            return {}

    def _merge_vulnerability_findings(
        self,
        nuclei_findings: List[Dict[str, Any]],
        nmap_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Merge nuclei and nmap findings into a unified list.

        Deduplicates by CVE ID (case-insensitive) where possible.

        Args:
            nuclei_findings: List of nuclei vulnerability findings
            nmap_result: Nmap vulnerability result dictionary

        Returns:
            Merged list of vulnerability findings
        """
        combined = []
        seen_cves = set()  # Stores uppercase CVE IDs for case-insensitive dedup

        # Add nuclei findings first (primary)
        for finding in nuclei_findings:
            cve_id = finding.get('cve_id')
            if cve_id:
                # Normalize to uppercase for deduplication
                seen_cves.add(cve_id.upper())
            combined.append({
                'source': 'nuclei',
                'cve_id': cve_id,
                'severity': finding.get('severity', 'unknown'),
                'title': finding.get('template_name', ''),
                'description': finding.get('description', ''),
                'cvss_score': finding.get('cvss_score'),
                'template_id': finding.get('template_id', ''),
                'reference': finding.get('reference', []),
            })

        # Add nmap findings (avoid duplicates - case-insensitive)
        nmap_vulns = nmap_result.get('vulnerabilities', [])
        for vuln in nmap_vulns:
            cve_id = vuln.get('cve_id')
            # Skip if already found by nuclei (case-insensitive comparison)
            if cve_id and cve_id.upper() in seen_cves:
                continue
            if cve_id:
                seen_cves.add(cve_id.upper())
            combined.append({
                'source': 'nmap',
                'cve_id': cve_id,
                'severity': vuln.get('severity', 'unknown'),
                'title': f"CVE: {cve_id}" if cve_id else 'Unknown vulnerability',
                'description': vuln.get('description', ''),
                'cvss_score': vuln.get('cvss'),
                'template_id': None,
                'reference': [],
            })

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        combined.sort(key=lambda x: severity_order.get(x['severity'], 5))

        return combined

    def step8_analyze(
        self,
        scan_id: str,
        scan_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Step 8: Run analysis if enabled.

        Args:
            scan_id: Scan session ID
            scan_data: Collected scan data for analysis

        Returns:
            Analysis results dictionary or None
        """
        if not self.analysis_service or not self.analysis_service.is_auto_analyze_enabled():
            return None

        logger.info(f"Running analysis for scan {scan_id}")

        try:
            analysis_results = self.analysis_service.analyze_scan_results(scan_id, scan_data)
            if analysis_results:
                logger.info(f"Analysis completed: {analysis_results.get('findings_count', 0)} findings")
            return analysis_results
        except Exception as e:
            logger.error(f"Analysis failed for scan {scan_id}: {e}")
            return None

    # =========================================================================
    # Main Workflow Execution
    # =========================================================================

    def execute_workflow(
        self,
        scan_id: str,
        domain: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete scan workflow for a domain.

        Workflow Steps:
        1. Subdomain discovery (subfinder)
        2. DNS resolution (dnsx)
        3. Port scanning (naabu)
        4. HTTP probing (httpx)
        5. TLS verification (tlsx)
        6. Service detection (nmap)
        7. Vulnerability detection (nmap)
        8. Analysis (if enabled)

        Args:
            scan_id: Existing scan session ID
            domain: Domain to scan
            timeout: Optional timeout in seconds

        Returns:
            Dictionary containing scan results
        """
        # Validate domain
        domain = validate_domain(domain)
        logger.info(f"Executing scan workflow for {domain} (scan_id: {scan_id})")

        # Step 1: Subdomain discovery
        subdomains = self.step1_discover_subdomains(domain, scan_id, timeout)

        # Step 2: DNS resolution
        active_subdomains, dns_results = self.step2_resolve_dns(subdomains, timeout)

        # Step 3: Port scanning
        ports_found = self.step3_scan_ports(active_subdomains, scan_id, timeout)

        # Step 4: HTTP probing (before TLS to identify web services)
        httpx_targets, httpx_results = self.step4_probe_http(ports_found, timeout)

        # Ensure domain exists in database
        if not self.db.domain_exists(domain):
            self.db.add_domain(domain, is_primary=True)

        # Categorize ports as web or non-web
        web_service_ports, non_web_ports, non_web_port_info_list = self._categorize_ports(
            httpx_targets, httpx_results, scan_id
        )

        # Step 5: TLS verification (only for non-web service ports)
        logger.info(
            f"TLS verification: {len(non_web_port_info_list)} non-web ports "
            f"(skipping {len(web_service_ports)} web service ports)"
        )
        tlsx_results = self.step5_verify_tls(non_web_port_info_list, timeout)

        # Step 6: Service detection for non-web ports
        nmap_service_results = self.step6_detect_services(non_web_ports)

        # Step 7: Vulnerability detection (nuclei + nmap NSE)
        vuln_results = self.step7_detect_vulnerabilities(nmap_service_results, non_web_ports)

        # Step 8: Run analysis
        scan_data = {
            'scan_id': scan_id,
            'domain': domain,
            'subfinder_results': [{'subdomain': s} for s in subdomains],
            'dnsx_results': dns_results,
            'naabu_results': ports_found,
            'httpx_results': list(httpx_results.values()),
            'tlsx_results': tlsx_results,
            'nmap_service_results': nmap_service_results,
            'vuln_results': vuln_results,  # nuclei + nmap NSE findings
            'web_service_ports': list(web_service_ports)
        }
        analysis_results = self.step8_analyze(scan_id, scan_data)

        # Calculate findings count
        findings_count = analysis_results.get('findings_count', 0) if analysis_results else 0

        return {
            'success': True,
            'scan_id': scan_id,
            'domain': domain,
            'subdomains_found': len(subdomains),
            'active_subdomains': len(active_subdomains),
            'ports_found': len(ports_found),
            'web_services': len(web_service_ports),
            'non_web_services': len(non_web_ports),
            'findings_count': findings_count,
            'analysis': analysis_results
        }

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _categorize_ports(
        self,
        httpx_targets: List[Tuple],
        httpx_results: Dict[str, Any],
        scan_id: str
    ) -> Tuple[set, List[Tuple[str, int]], List[Dict[str, Any]]]:
        """
        Categorize ports as web or non-web based on httpx results.

        Returns:
            Tuple of (web_service_ports set, non_web_ports list, non_web_port_info_list)
        """
        web_service_ports = set()
        non_web_ports = []
        non_web_port_info_list = []

        for target_url, port_info in httpx_targets:
            httpx_result = httpx_results.get(target_url)
            host = extract_host_from_port_info(port_info)
            port = port_info.get('port')

            if httpx_result:
                is_web, confidence = is_web_service(httpx_result)
                if is_web:
                    web_service_ports.add(f"{host}:{port}")
                    continue

            # Collect non-web port for service detection and TLS verification
            if host:
                non_web_ports.append((host, port))
                non_web_port_info_list.append(port_info)

        return web_service_ports, non_web_ports, non_web_port_info_list

    def _map_service_to_severity(self, service: str) -> str:
        """
        Map detected service name to severity level.

        Args:
            service: Service name (e.g., 'mysql', 'ssh', 'unknown')

        Returns:
            Severity level: 'critical', 'high', 'medium', or 'low'
        """
        service_lower = service.lower().strip()

        # Critical services (databases, caches, search engines)
        if any(svc in service_lower for svc in self.critical_services):
            return 'critical'

        # High risk (unencrypted protocols, legacy services)
        if any(svc in service_lower for svc in self.high_risk_services):
            return 'high'

        # Medium risk (expected services but need verification)
        if any(svc in service_lower for svc in self.medium_risk_services):
            return 'medium'

        # Low risk (generally safe services)
        if any(svc in service_lower for svc in self.low_risk_services):
            return 'low'

        # Default to medium for unknown services
        return 'medium'
