"""
Scan management service.

Handles business logic for scan operations including
creation, execution, status tracking, and results retrieval.
"""

from typing import List, Dict, Any, Optional
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain
from src.cli.commands import run_subfinder, run_naabu, run_dnsx
from src.utils.timezone import get_ist_now


class ScanService:
    """Service for managing scans."""

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize scan service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

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

        try:
            # Step 1: Subdomain discovery (subfinder)
            subdomains = run_subfinder(domain, timeout=timeout)

            # Step 2: DNS resolution (dnsx)
            active_subdomains = []
            if subdomains:
                dns_results = run_dnsx(subdomains, record_types=['a'], timeout=timeout)
                active_subdomains = [r['host'] for r in dns_results if r.get('a')]

            # Step 3: Port scanning (naabu)
            ports_found = []
            if active_subdomains:
                ports_found = run_naabu(active_subdomains, timeout=timeout)

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

            # Alert for open ports
            for port_info in ports_found:
                alerts.append({
                    'scan_id': scan_id,
                    'domain': port_info.get('host', ''),
                    'vulnerability_type': 'open_port',
                    'severity': 'low',
                    'description': f"Open port {port_info.get('port')} ({port_info.get('protocol', 'tcp')})",
                    'tool_source': 'naabu',
                    'discovered_at': get_ist_now()
                })

            # Store alerts
            if alerts:
                self.db.store_alerts(alerts)

            # Update scan status
            self.db.update_scan_status(
                scan_id,
                'completed',
                end_time=get_ist_now(),
                findings_count=len(alerts)
            )

            return {
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

        except Exception as e:
            # Update scan status to failed
            self.db.update_scan_status(
                scan_id,
                'failed',
                end_time=get_ist_now()
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

        # Get alerts (subdomains/ports) for this scan
        alerts_result = self.db.get_alerts(scan_id=scan_id, limit=10000)
        alerts = alerts_result.get('alerts', [])

        ports = []
        subdomains = set()

        for alert in alerts:
            subdomain = alert.get('domain', '')
            subdomains.add(subdomain)

            # Parse port from description
            port_num = 0
            protocol = 'tcp'
            desc = alert.get('description', '')

            if 'Open port' in desc:
                parts = desc.replace('Open port ', '').split(' ')
                try:
                    port_num = int(parts[0])
                    if len(parts) > 1:
                        protocol = parts[1].strip('()')
                except:
                    pass

            if port_num > 0:  # Only add if we found a port
                ports.append({
                    'subdomain': subdomain,
                    'port': port_num,
                    'protocol': protocol,
                    'ip': '',
                    'discovered_at': alert.get('discovered_at', '')
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
                'start_time': scan_info.get('start_time', ''),
                'end_time': scan_info.get('end_time', ''),
                'findings_count': scan_info.get('findings_count', 0),
                'total_subdomains': len(subdomains),
                'total_ports': len(ports)
            },
            'subdomains': [{'subdomain': s, 'ip_address': '', 'discovered_at': ''} for s in sorted(subdomains)],
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
