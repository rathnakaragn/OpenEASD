"""
Service Vulnerability Detector for OpenEASD Analysis Layer.

Analyzes nmap service detection results to identify security risks:
- Known vulnerable service versions
- Outdated software versions
- Services with default configurations
- Exposed sensitive services
"""

from typing import Dict, List, Any
from src.analysis.detectors.base_detector import BaseDetector
from src.analysis.config import get_analysis_config


class ServiceVulnerabilityDetector(BaseDetector):
    """Analyzes nmap service detection results for security vulnerabilities."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize service detector.

        Args:
            config: Detector configuration
        """
        super().__init__(config)
        self.analysis_config = get_analysis_config()

        # Load service risk classifications from config (using getter methods for consistency)
        self.critical_services = self.analysis_config.get_critical_services()
        self.high_risk_services = self.analysis_config.get_high_risk_services()
        self.medium_risk_services = self.analysis_config.get_medium_risk_services()

        # Service-specific metadata for remediation
        self.service_info = {
            'mysql': {
                'name': 'MySQL',
                'type': 'database',
                'remediation': (
                    'Restrict MySQL access to internal networks only. '
                    'Enable TLS encryption and strong authentication.'
                ),
                'cwe_id': 'CWE-200'
            },
            'postgresql': {
                'name': 'PostgreSQL',
                'type': 'database',
                'remediation': 'Restrict PostgreSQL access to internal networks. Enable SSL and use strong passwords.',
                'cwe_id': 'CWE-200'
            },
            'mongodb': {
                'name': 'MongoDB',
                'type': 'database',
                'remediation': 'Enable authentication (disabled by default). Restrict network access. Enable TLS.',
                'cwe_id': 'CWE-200'
            },
            'redis': {
                'name': 'Redis',
                'type': 'cache',
                'remediation': (
                    'Enable authentication with requirepass. '
                    'Restrict network access. Use TLS in production.'
                ),
                'cwe_id': 'CWE-200'
            },
            'elasticsearch': {
                'name': 'Elasticsearch',
                'type': 'search',
                'remediation': 'Enable X-Pack security. Use authentication and TLS. Restrict network access.',
                'cwe_id': 'CWE-200'
            },
            'telnet': {
                'name': 'Telnet',
                'type': 'remote_access',
                'remediation': 'Disable Telnet entirely. Use SSH for secure remote access.',
                'cwe_id': 'CWE-319'
            },
            'ftp': {
                'name': 'FTP',
                'type': 'file_transfer',
                'remediation': 'Replace FTP with SFTP or FTPS. FTP transmits credentials in plaintext.',
                'cwe_id': 'CWE-319'
            },
            'vnc': {
                'name': 'VNC',
                'type': 'remote_desktop',
                'remediation': 'Use strong passwords. Enable encryption. Access only through VPN.',
                'cwe_id': 'CWE-16'
            },
            'ssh': {
                'name': 'SSH',
                'type': 'remote_access',
                'remediation': 'Disable password authentication. Use key-based auth. Restrict access by IP.',
                'cwe_id': 'CWE-16'
            },
            'smtp': {
                'name': 'SMTP',
                'type': 'mail',
                'remediation': 'Ensure relay restrictions are configured. Enable TLS. Check for open relay.',
                'cwe_id': 'CWE-16'
            },
            'http': {
                'name': 'HTTP',
                'type': 'web',
                'remediation': 'Redirect to HTTPS. Ensure TLS is properly configured.',
                'cwe_id': 'CWE-319'
            },
            'https': {
                'name': 'HTTPS',
                'type': 'web',
                'remediation': 'Verify TLS configuration. Check for weak ciphers and certificate validity.',
                'cwe_id': None
            }
        }

    def analyze(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze nmap service detection results for vulnerabilities.

        Args:
            scan_data: Dictionary containing scan results
                Expected keys:
                - 'nmap_service_results': Dict mapping "host:port" to service detection results

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Get nmap service detection results
        nmap_results = scan_data.get('nmap_service_results', {})
        if not nmap_results:
            return findings

        # Analyze each detected service
        for port_key, service_data in nmap_results.items():
            if service_data.get('status') != 'success':
                continue

            # Parse host:port
            try:
                host, port_str = port_key.split(':')
                port = int(port_str)
            except (ValueError, AttributeError):
                continue

            service = service_data.get('service', 'unknown').lower()
            version = service_data.get('version', '')
            product = service_data.get('product', '')
            confidence = service_data.get('confidence', 0)

            # Skip unknown services with low confidence
            if service == 'unknown' and confidence < 50:
                continue

            # Check for critical exposed services (databases, etc.)
            if any(svc in service for svc in self.critical_services):
                finding = self._create_critical_service_finding(
                    host, port, service, version, product, confidence
                )
                findings.append(finding)

            # Check for high-risk services (unencrypted protocols, etc.)
            elif any(svc in service for svc in self.high_risk_services):
                finding = self._create_high_risk_service_finding(
                    host, port, service, version, product, confidence
                )
                findings.append(finding)

            # Check for medium-risk services
            elif any(svc in service for svc in self.medium_risk_services):
                finding = self._create_medium_risk_service_finding(
                    host, port, service, version, product, confidence
                )
                findings.append(finding)

            # Check for version-specific vulnerabilities
            if version:
                vuln_finding = self._check_version_vulnerabilities(
                    host, port, service, version, product
                )
                if vuln_finding:
                    findings.append(vuln_finding)

        return findings

    def _create_critical_service_finding(
        self, host: str, port: int, service: str, version: str, product: str, confidence: int
    ) -> Dict[str, Any]:
        """Create finding for critical exposed service (databases, etc.)."""
        service_meta = self.service_info.get(service, {})
        service_name = service_meta.get('name', service.upper())

        version_str = f" {version}" if version else ""
        product_str = product or service_name

        return self._create_finding(
            finding_type='critical_service_exposed',
            title=f'Critical Service Exposed: {product_str}{version_str} (Port {port})',
            description=(
                f'{service_name} is publicly accessible on port {port}. '
                f'This service type should never be exposed to the internet. '
                f'Attackers can attempt authentication bypass, data extraction, or exploitation.'
            ),
            affected_asset=host,
            severity_hint='critical',
            port=port,
            protocol='tcp',
            service_name=service,
            service_version=version,
            product=product,
            confidence=confidence,
            cwe_id=service_meta.get('cwe_id', 'CWE-200'),
            evidence={
                'port': port,
                'host': host,
                'service': service,
                'version': version,
                'product': product,
                'confidence': confidence,
                'service_type': service_meta.get('type', 'unknown')
            },
            remediation=service_meta.get(
                'remediation',
                f'Restrict {service_name} access to internal networks only. Enable authentication and encryption.'
            )
        )

    def _create_high_risk_service_finding(
        self, host: str, port: int, service: str, version: str, product: str, confidence: int
    ) -> Dict[str, Any]:
        """Create finding for high-risk service exposure."""
        service_meta = self.service_info.get(service, {})
        service_name = service_meta.get('name', service.upper())

        version_str = f" {version}" if version else ""
        product_str = product or service_name

        return self._create_finding(
            finding_type='high_risk_service_exposed',
            title=f'High-Risk Service Exposed: {product_str}{version_str} (Port {port})',
            description=(
                f'{service_name} service is exposed on port {port}. '
                f'This service type has known security concerns and should be restricted or replaced.'
            ),
            affected_asset=host,
            severity_hint='high',
            port=port,
            protocol='tcp',
            service_name=service,
            service_version=version,
            product=product,
            confidence=confidence,
            cwe_id=service_meta.get('cwe_id', 'CWE-16'),
            evidence={
                'port': port,
                'host': host,
                'service': service,
                'version': version,
                'product': product,
                'confidence': confidence
            },
            remediation=service_meta.get(
                'remediation',
                f'Replace {service_name} with a more secure alternative or restrict access.'
            )
        )

    def _create_medium_risk_service_finding(
        self, host: str, port: int, service: str, version: str, product: str, confidence: int
    ) -> Dict[str, Any]:
        """Create finding for medium-risk service exposure."""
        service_meta = self.service_info.get(service, {})
        service_name = service_meta.get('name', service.upper())

        version_str = f" {version}" if version else ""
        product_str = product or service_name

        return self._create_finding(
            finding_type='service_exposed',
            title=f'Service Detected: {product_str}{version_str} (Port {port})',
            description=(
                f'{service_name} service detected on port {port}. '
                f'Verify this service is intentionally exposed and properly secured.'
            ),
            affected_asset=host,
            severity_hint='medium',
            port=port,
            protocol='tcp',
            service_name=service,
            service_version=version,
            product=product,
            confidence=confidence,
            cwe_id=service_meta.get('cwe_id', 'CWE-16'),
            evidence={
                'port': port,
                'host': host,
                'service': service,
                'version': version,
                'product': product,
                'confidence': confidence
            },
            remediation=service_meta.get(
                'remediation',
                f'Review {service_name} configuration. Ensure proper authentication and encryption.'
            )
        )

    def _check_version_vulnerabilities(
        self, host: str, port: int, service: str, version: str, product: str
    ) -> Dict[str, Any]:
        """
        Check for known vulnerable versions.

        This is a placeholder for future CVE integration.
        Currently checks for obviously outdated versions.
        """
        # Known outdated/vulnerable version patterns
        # In production, this would query NVD or a CVE database
        vulnerable_patterns = {
            'openssh': ['4.', '5.', '6.'],  # Very old SSH versions
            'apache': ['1.', '2.0', '2.2'],  # Old Apache versions
            'nginx': ['0.', '1.0', '1.2'],  # Old Nginx versions
            'mysql': ['4.', '5.0', '5.1', '5.5'],  # Old MySQL versions
            'postgresql': ['7.', '8.', '9.0', '9.1', '9.2'],  # Old PostgreSQL
            'redis': ['2.', '3.0', '3.2'],  # Old Redis versions
            'mongodb': ['2.', '3.0', '3.2'],  # Old MongoDB versions
        }

        service_lower = service.lower()
        for svc_name, vuln_versions in vulnerable_patterns.items():
            if svc_name in service_lower:
                for vuln_prefix in vuln_versions:
                    if version.startswith(vuln_prefix):
                        return self._create_finding(
                            finding_type='outdated_service_version',
                            title=f'Outdated {service.upper()} Version: {version} (Port {port})',
                            description=(
                                f'{service.upper()} version {version} is outdated and may contain '
                                f'known vulnerabilities. Update to the latest stable version.'
                            ),
                            affected_asset=host,
                            severity_hint='high',
                            port=port,
                            protocol='tcp',
                            service_name=service,
                            service_version=version,
                            product=product,
                            cwe_id='CWE-1104',  # Use of Unmaintained Third Party Components
                            evidence={
                                'port': port,
                                'host': host,
                                'service': service,
                                'version': version,
                                'vulnerability': 'outdated_version'
                            },
                            remediation=f'Update {service.upper()} to the latest stable version immediately.'
                        )

        return None

    def get_service_risk_level(self, service: str) -> str:
        """
        Get risk level for a service.

        Args:
            service: Service name

        Returns:
            Risk level: critical/high/medium/low/info
        """
        service_lower = service.lower()

        if any(svc in service_lower for svc in self.critical_services):
            return 'critical'
        elif any(svc in service_lower for svc in self.high_risk_services):
            return 'high'
        elif any(svc in service_lower for svc in self.medium_risk_services):
            return 'medium'
        elif service_lower in ['http', 'https']:
            return 'low'
        else:
            return 'info'
