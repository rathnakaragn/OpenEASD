"""
Service Vulnerability Detector for OpenEASD Analysis Layer.

Analyzes nmap service detection results to identify security risks:
- Known vulnerable service versions
- Outdated software versions
- Services with default configurations
- Exposed sensitive services
"""

import re
from typing import Dict, List, Any, Optional
from src.analysis.detectors.base_detector import BaseDetector
from src.analysis.config import get_analysis_config
from src.analysis.constants import VULNERABLE_VERSIONS, TLS_VERSION_RISK, WEAK_CIPHER_PATTERNS


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

        # Analyze TLS quality from tlsx results
        tlsx_results = scan_data.get('tlsx_results', {})
        for port_key, tlsx_data in tlsx_results.items():
            if not tlsx_data or tlsx_data.get('status') != 'success':
                continue

            # Parse host:port
            try:
                host, port_str = port_key.split(':')
                port = int(port_str)
            except (ValueError, AttributeError):
                continue

            # Check TLS quality
            tls_findings = self._check_tls_quality(host, port, tlsx_data)
            findings.extend(tls_findings)

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
    ) -> Optional[Dict[str, Any]]:
        """
        Check for known vulnerable versions using regex patterns.

        Uses VULNERABLE_VERSIONS from constants for pattern matching with CVE data.
        """
        if not version:
            return None

        service_lower = service.lower()
        product_lower = (product or '').lower()

        # Check against known vulnerable version patterns
        for svc_name, vuln_list in VULNERABLE_VERSIONS.items():
            # Match by service name or product name
            if svc_name in service_lower or svc_name in product_lower:
                for vuln_info in vuln_list:
                    pattern = vuln_info.get('pattern', '')
                    try:
                        if re.search(pattern, version, re.IGNORECASE):
                            severity = vuln_info.get('severity', 'high')
                            cve = vuln_info.get('cve', 'Unknown')
                            description = vuln_info.get('description', 'Vulnerable version detected')

                            return self._create_finding(
                                finding_type='vulnerable_service_version',
                                title=f'Vulnerable {service.upper()} Version: {version} ({cve})',
                                description=(
                                    f'{service.upper()} version {version} is vulnerable. '
                                    f'{description}'
                                ),
                                affected_asset=host,
                                severity_hint=severity,
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
                                    'cve': cve,
                                    'vulnerability': 'known_vulnerable_version'
                                },
                                remediation=f'Update {service.upper()} to the latest stable version immediately. {cve} affects this version.'
                            )
                    except re.error:
                        # Invalid regex pattern - skip
                        continue

        return None

    def _check_tls_quality(
        self, host: str, port: int, tlsx_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Check TLS quality from tlsx results.

        Detects:
        - Weak TLS versions (SSL2, SSL3, TLS 1.0, TLS 1.1)
        - Weak cipher suites
        - Certificate issues
        """
        findings = []

        if not tlsx_result or not tlsx_result.get('tls_enabled'):
            return findings

        # Check TLS version
        tls_version = tlsx_result.get('tls_version', '').lower().replace(' ', '').replace('.', '')
        if tls_version:
            for version_key, risk_info in TLS_VERSION_RISK.items():
                if version_key in tls_version:
                    severity = risk_info.get('severity', 'medium')
                    # Only report if severity is high or critical (deprecated versions)
                    if severity in ['critical', 'high']:
                        finding = self._create_finding(
                            finding_type='weak_tls_version',
                            title=f'Weak TLS Version: {tlsx_result.get("tls_version", tls_version)} (Port {port})',
                            description=risk_info.get('description', 'Weak TLS version detected'),
                            affected_asset=host,
                            severity_hint=severity,
                            port=port,
                            protocol='tcp',
                            cwe_id='CWE-326',  # Inadequate Encryption Strength
                            evidence={
                                'port': port,
                                'host': host,
                                'tls_version': tlsx_result.get('tls_version', tls_version),
                                'vulnerability': 'weak_tls'
                            },
                            remediation='Upgrade to TLS 1.2 or TLS 1.3. Disable older TLS versions.'
                        )
                        findings.append(finding)
                    break

        # Check cipher suites
        cipher = tlsx_result.get('cipher', '')
        if cipher:
            for cipher_info in WEAK_CIPHER_PATTERNS:
                pattern = cipher_info.get('pattern', '')
                try:
                    if re.search(pattern, cipher, re.IGNORECASE):
                        finding = self._create_finding(
                            finding_type='weak_cipher_suite',
                            title=f'Weak Cipher Suite: {cipher} (Port {port})',
                            description=cipher_info.get('description', 'Weak cipher detected'),
                            affected_asset=host,
                            severity_hint=cipher_info.get('severity', 'medium'),
                            port=port,
                            protocol='tcp',
                            cwe_id='CWE-327',  # Use of a Broken or Risky Cryptographic Algorithm
                            evidence={
                                'port': port,
                                'host': host,
                                'cipher': cipher,
                                'vulnerability': 'weak_cipher'
                            },
                            remediation='Configure server to use strong cipher suites only. Disable weak ciphers.'
                        )
                        findings.append(finding)
                        break  # One finding per port for weak ciphers
                except re.error:
                    continue

        # Check certificate expiration (if available)
        cert_expired = tlsx_result.get('cert_expired', False)
        if cert_expired:
            finding = self._create_finding(
                finding_type='expired_certificate',
                title=f'Expired TLS Certificate (Port {port})',
                description='The TLS certificate has expired, causing security warnings and potential MITM vulnerability.',
                affected_asset=host,
                severity_hint='high',
                port=port,
                protocol='tcp',
                cwe_id='CWE-295',  # Improper Certificate Validation
                evidence={
                    'port': port,
                    'host': host,
                    'vulnerability': 'expired_certificate'
                },
                remediation='Renew the TLS certificate immediately.'
            )
            findings.append(finding)

        return findings

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
