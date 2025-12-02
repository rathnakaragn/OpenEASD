"""
Port Vulnerability Detector for OpenEASD Analysis Layer.

Analyzes open ports from Naabu scan results to identify security risks:
- High-risk ports (databases, admin interfaces, vulnerable services)
- Publicly exposed sensitive services
- Unnecessary open ports
- Port-based vulnerabilities

Refactored to use centralized constants from src/analysis/constants.py
"""

from typing import Dict, List, Any
from src.analysis.detectors.base_detector import BaseDetector
from src.analysis.config import get_analysis_config
from src.analysis.constants import (
    PORT_INFO,
    DATABASE_PORTS,
    ADMIN_PORTS,
    REMOTE_ACCESS_PORTS,
    UNENCRYPTED_PROTOCOL_PORTS,
    get_port_risk_level,
    get_port_category
)


class PortVulnerabilityDetector(BaseDetector):
    """Analyzes open ports for security vulnerabilities."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize port detector.

        Args:
            config: Detector configuration
        """
        super().__init__(config)
        self.analysis_config = get_analysis_config()

        # Load port classifications from config methods with constants as fallback
        # This maintains backward compatibility while centralizing defaults
        try:
            self.database_ports = self.analysis_config.get_database_ports()
        except AttributeError:
            self.database_ports = DATABASE_PORTS

        try:
            self.admin_ports = self.analysis_config.get_admin_ports()
        except AttributeError:
            self.admin_ports = ADMIN_PORTS

        try:
            self.remote_access_ports = self.analysis_config.get_remote_access_ports()
        except AttributeError:
            self.remote_access_ports = REMOTE_ACCESS_PORTS

        self.unencrypted_protocols_set = UNENCRYPTED_PROTOCOL_PORTS

        # Load high/medium risk ports from config (for backwards compatibility)
        self.high_risk_ports = self.analysis_config.get_high_risk_ports()
        self.medium_risk_ports = self.analysis_config.get_medium_risk_ports()

        # Get unencrypted protocol config (for encrypted alternatives info)
        self.unencrypted_protocols = self.analysis_config.get_unencrypted_protocols()

        # Use centralized port info
        self.port_info = PORT_INFO

    def analyze(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze naabu port scan results for vulnerabilities.

        Args:
            scan_data: Dictionary containing scan results
                Expected keys:
                - 'naabu_results': List of open port dictionaries
                - 'tlsx_results': Optional dict mapping "host:port" to TLS probe results

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Get naabu results
        naabu_results = scan_data.get('naabu_results', [])
        if not naabu_results:
            return findings

        # Get tlsx results for TLS verification (optional)
        # Format: {"host:port": {"tls_enabled": True/False, "tls_version": "...", ...}}
        tlsx_results = scan_data.get('tlsx_results', {})

        # Analyze each open port
        for port_info in naabu_results:
            port = port_info.get('port')
            host = port_info.get('target_host', port_info.get('subdomain', 'unknown'))
            protocol = port_info.get('protocol', 'tcp')
            ip = port_info.get('ip', '')

            if not port:
                continue

            # Check for high-risk ports
            if port in self.high_risk_ports:
                finding = self._create_high_risk_port_finding(port, host, protocol, ip)
                findings.append(finding)

            # Check for exposed databases
            if port in self.database_ports:
                finding = self._create_database_exposure_finding(port, host, protocol, ip)
                findings.append(finding)

            # Check for admin interfaces
            if port in self.admin_ports:
                finding = self._create_admin_interface_finding(port, host, protocol, ip)
                findings.append(finding)

            # Check for remote access services
            if port in self.remote_access_ports:
                finding = self._create_remote_access_finding(port, host, protocol, ip)
                findings.append(finding)

            # Check for medium-risk ports
            if port in self.medium_risk_ports and port not in self.high_risk_ports:
                finding = self._create_medium_risk_port_finding(port, host, protocol, ip)
                findings.append(finding)

            # Check for unencrypted protocols (plaintext services without TLS)
            if port in self.unencrypted_protocols_set:
                # Check if tlsx verified TLS status for this host:port
                tlsx_key = f"{host}:{port}"
                tlsx_probe = tlsx_results.get(tlsx_key, {})

                # Determine if TLS is enabled
                tls_enabled = tlsx_probe.get('tls_enabled')

                if tls_enabled is False:
                    # tlsx confirmed NO TLS - definitely unencrypted
                    finding = self._create_unencrypted_protocol_finding(
                        port, host, protocol, ip,
                        verified_by_tlsx=True,
                        tlsx_error=tlsx_probe.get('error')
                    )
                    findings.append(finding)
                elif tls_enabled is None and not tlsx_results:
                    # No tlsx data available - fall back to port-based assumption
                    finding = self._create_unencrypted_protocol_finding(
                        port, host, protocol, ip,
                        verified_by_tlsx=False
                    )
                    findings.append(finding)
                # If tls_enabled is True, service has TLS - no finding needed

        return findings

    def _create_high_risk_port_finding(
        self, port: int, host: str, protocol: str, ip: str
    ) -> Dict[str, Any]:
        """Create finding for high-risk port exposure."""
        port_data = self.port_info.get(port, {})
        service_name = port_data.get('name', f'Port {port}')
        description = port_data.get('description', 'High-risk service exposed')

        return self._create_finding(
            finding_type='high_risk_port_exposed',
            title=f'High-Risk Service Exposed: {service_name} (Port {port})',
            description=f'{description}. This port should not be publicly accessible.',
            affected_asset=host,
            severity_hint='high',
            port=port,
            protocol=protocol,
            ip=ip,
            service_name=service_name,
            cwe_id='CWE-16',  # Configuration
            evidence={
                'port': port,
                'protocol': protocol,
                'host': host,
                'ip': ip,
                'service': service_name
            },
            remediation=port_data.get('remediation', f'Restrict access to {service_name} or disable the service if not needed')
        )

    def _create_database_exposure_finding(
        self, port: int, host: str, protocol: str, ip: str
    ) -> Dict[str, Any]:
        """Create finding for exposed database port."""
        port_data = self.port_info.get(port, {})
        service_name = port_data.get('name', f'Database Port {port}')

        return self._create_finding(
            finding_type='database_port_exposed',
            title=f'Database Publicly Accessible: {service_name} (Port {port})',
            description=f'{service_name} database is accessible from the internet. '
                       f'Database services should only be accessible from internal networks '
                       f'or through secure VPN connections.',
            affected_asset=host,
            severity_hint='critical',
            port=port,
            protocol=protocol,
            ip=ip,
            service_name=service_name,
            cwe_id='CWE-200',  # Exposure of Sensitive Information
            evidence={
                'port': port,
                'protocol': protocol,
                'host': host,
                'ip': ip,
                'service': service_name,
                'finding': 'database_exposed_to_internet'
            },
            remediation=f'Implement firewall rules to restrict {service_name} access to internal networks only. '
                       f'Enable authentication and encryption. Consider using SSH tunnels or VPN.'
        )

    def _create_admin_interface_finding(
        self, port: int, host: str, protocol: str, ip: str
    ) -> Dict[str, Any]:
        """Create finding for exposed administrative interface."""
        return self._create_finding(
            finding_type='admin_interface_exposed',
            title=f'Administrative Interface Exposed (Port {port})',
            description=f'Administrative interface or control panel detected on port {port}. '
                       f'These interfaces should be protected and not publicly accessible.',
            affected_asset=host,
            severity_hint='high',
            port=port,
            protocol=protocol,
            ip=ip,
            cwe_id='CWE-425',  # Direct Request
            evidence={
                'port': port,
                'protocol': protocol,
                'host': host,
                'ip': ip
            },
            remediation='Restrict admin interface access using IP whitelisting, VPN, or remove public accessibility.'
        )

    def _create_remote_access_finding(
        self, port: int, host: str, protocol: str, ip: str
    ) -> Dict[str, Any]:
        """Create finding for remote access service exposure."""
        port_data = self.port_info.get(port, {})
        service_name = port_data.get('name', f'Port {port}')
        risk_level = port_data.get('risk', 'high')

        # Special handling for particularly risky services
        if port == 23:  # Telnet
            severity = 'critical'
            title = 'Telnet Service Exposed - Unencrypted Remote Access'
            description = 'Telnet transmits all data including passwords in plain text. This is a critical security risk.'
        else:
            severity = 'high' if risk_level == 'critical' else 'medium'
            title = f'Remote Access Service Exposed: {service_name} (Port {port})'
            description = f'{service_name} remote access service is publicly accessible.'

        return self._create_finding(
            finding_type='remote_access_exposed',
            title=title,
            description=description,
            affected_asset=host,
            severity_hint=severity,
            port=port,
            protocol=protocol,
            ip=ip,
            service_name=service_name,
            cwe_id='CWE-288',  # Authentication Bypass
            evidence={
                'port': port,
                'protocol': protocol,
                'host': host,
                'ip': ip,
                'service': service_name
            },
            remediation=port_data.get('remediation', f'Use VPN for remote access. Disable {service_name} if not needed. Implement strong authentication.')
        )

    def _create_medium_risk_port_finding(
        self, port: int, host: str, protocol: str, ip: str
    ) -> Dict[str, Any]:
        """Create finding for medium-risk port exposure."""
        port_data = self.port_info.get(port, {})
        service_name = port_data.get('name', f'Port {port}')

        return self._create_finding(
            finding_type='medium_risk_port_exposed',
            title=f'Service Exposed: {service_name} (Port {port})',
            description=f'{service_name} service detected on port {port}. '
                       f'Verify this service is intentionally exposed and properly secured.',
            affected_asset=host,
            severity_hint='medium',
            port=port,
            protocol=protocol,
            ip=ip,
            service_name=service_name,
            evidence={
                'port': port,
                'protocol': protocol,
                'host': host,
                'ip': ip,
                'service': service_name
            },
            remediation=f'Review if {service_name} needs to be publicly accessible. '
                       f'Implement authentication and use TLS/SSL if available.'
        )

    def _create_unencrypted_protocol_finding(
        self, port: int, host: str, protocol: str, ip: str,
        verified_by_tlsx: bool = False, tlsx_error: str = None
    ) -> Dict[str, Any]:
        """Create finding for unencrypted protocol that should use TLS.

        Args:
            port: Port number
            host: Target hostname
            protocol: Protocol (tcp/udp)
            ip: IP address
            verified_by_tlsx: Whether tlsx was used to verify no TLS
            tlsx_error: Error from tlsx if any
        """
        proto_info = self.unencrypted_protocols.get(port, {})
        service_name = proto_info.get('name', f'Port {port}')
        encrypted_name = proto_info.get('encrypted_name', 'TLS')
        encrypted_port = proto_info.get('encrypted_port')
        config_severity = proto_info.get('severity', 'high')

        # Severity based on TLS verification status:
        # - Verified no TLS by tlsx → CRITICAL (confirmed cleartext transmission)
        # - Unverified (fallback) → Use configured severity (lower confidence)
        if verified_by_tlsx:
            severity = 'critical'  # tlsx confirmed NO TLS - definitely unencrypted
            verification_note = " (Verified by tlsx - TLS handshake failed)"
        else:
            severity = config_severity  # Fallback to configured severity
            verification_note = " (Based on port number - unverified)"

        # Build remediation text
        if encrypted_port:
            remediation = (
                f'Migrate from {service_name} (port {port}) to {encrypted_name} (port {encrypted_port}). '
                f'Enable TLS/SSL encryption to protect data in transit. '
                f'Credentials and sensitive data are exposed in plaintext without encryption.'
            )
        else:
            remediation = (
                f'Enable TLS/SSL encryption for {service_name}. '
                f'Configure the service to require encrypted connections. '
                f'Credentials and sensitive data are exposed in plaintext without encryption.'
            )

        evidence = {
            'port': port,
            'protocol': protocol,
            'host': host,
            'ip': ip,
            'service': service_name,
            'encryption': 'none',
            'recommended_service': encrypted_name,
            'recommended_port': encrypted_port,
            'vulnerability': 'cleartext_transmission',
            'verified_by_tlsx': verified_by_tlsx
        }

        if tlsx_error:
            evidence['tlsx_error'] = tlsx_error

        return self._create_finding(
            finding_type='unencrypted_protocol',
            title=f'Unencrypted Protocol: {service_name} (Port {port}) - No TLS{verification_note}',
            description=(
                f'{service_name} is running without encryption on port {port}. '
                f'This service transmits data in plaintext, exposing credentials, '
                f'authentication tokens, and sensitive information to interception (MITM attacks). '
                f'Use {encrypted_name} instead for secure communication.'
            ),
            affected_asset=host,
            severity_hint=severity,
            port=port,
            protocol=protocol,
            ip=ip,
            service_name=service_name,
            cwe_id='CWE-319',  # Cleartext Transmission of Sensitive Information
            evidence=evidence,
            remediation=remediation
        )

    def get_port_risk_level(self, port: int) -> str:
        """
        Get risk level for a port using centralized constants.

        Args:
            port: Port number

        Returns:
            Risk level: critical/high/medium/low/info
        """
        # Use centralized helper function from constants
        return get_port_risk_level(port)
