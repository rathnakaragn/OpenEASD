"""
Port Vulnerability Detector for OpenEASD Analysis Layer.

Analyzes open ports from Naabu scan results to identify security risks:
- High-risk ports (databases, admin interfaces, vulnerable services)
- Publicly exposed sensitive services
- Unnecessary open ports
- Port-based vulnerabilities
"""

from typing import Dict, List, Any
from src.analysis.detectors.base_detector import BaseDetector
from src.analysis.config import get_analysis_config


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

        # Load port lists from configuration
        self.high_risk_ports = self.analysis_config.get_high_risk_ports()
        self.medium_risk_ports = self.analysis_config.get_medium_risk_ports()

        # Additional port classifications
        self.database_ports = [3306, 5432, 27017, 6379, 1433, 5984, 9042, 7000, 7001]
        self.admin_ports = [2082, 2083, 2086, 2087, 8443, 10000]
        self.remote_access_ports = [21, 22, 23, 3389, 5900, 5901]

        # Unencrypted protocols that have encrypted alternatives
        # Format: plaintext_port -> {'name': ..., 'encrypted_port': ..., 'encrypted_name': ...}
        self.unencrypted_protocols = {
            21: {'name': 'FTP', 'encrypted_port': 990, 'encrypted_name': 'FTPS', 'severity': 'high'},
            23: {'name': 'Telnet', 'encrypted_port': 22, 'encrypted_name': 'SSH', 'severity': 'critical'},
            25: {'name': 'SMTP', 'encrypted_port': 465, 'encrypted_name': 'SMTPS', 'severity': 'high'},
            80: {'name': 'HTTP', 'encrypted_port': 443, 'encrypted_name': 'HTTPS', 'severity': 'medium'},
            110: {'name': 'POP3', 'encrypted_port': 995, 'encrypted_name': 'POP3S', 'severity': 'high'},
            143: {'name': 'IMAP', 'encrypted_port': 993, 'encrypted_name': 'IMAPS', 'severity': 'high'},
            389: {'name': 'LDAP', 'encrypted_port': 636, 'encrypted_name': 'LDAPS', 'severity': 'high'},
            1080: {'name': 'SOCKS', 'encrypted_port': None, 'encrypted_name': 'SOCKS5 over TLS', 'severity': 'high'},
            5432: {'name': 'PostgreSQL', 'encrypted_port': None, 'encrypted_name': 'PostgreSQL SSL', 'severity': 'critical'},
            3306: {'name': 'MySQL', 'encrypted_port': None, 'encrypted_name': 'MySQL SSL', 'severity': 'critical'},
            27017: {'name': 'MongoDB', 'encrypted_port': None, 'encrypted_name': 'MongoDB TLS', 'severity': 'critical'},
            6379: {'name': 'Redis', 'encrypted_port': None, 'encrypted_name': 'Redis TLS', 'severity': 'critical'},
        }

        # Port information map (loaded from config or defaults)
        self.port_info = self._load_port_info()

    def _load_port_info(self) -> Dict[int, Dict[str, str]]:
        """Load port information from configuration."""
        # Default port information
        default_info = {
            21: {'name': 'FTP', 'risk': 'high', 'desc': 'File Transfer Protocol - transmits credentials in plain text'},
            22: {'name': 'SSH', 'risk': 'low', 'desc': 'Secure Shell - encrypted remote access'},
            23: {'name': 'Telnet', 'risk': 'critical', 'desc': 'Unencrypted remote access protocol'},
            25: {'name': 'SMTP', 'risk': 'medium', 'desc': 'Mail server - potential spam relay'},
            80: {'name': 'HTTP', 'risk': 'low', 'desc': 'Unencrypted web traffic'},
            443: {'name': 'HTTPS', 'risk': 'info', 'desc': 'Encrypted web traffic'},
            3306: {'name': 'MySQL', 'risk': 'critical', 'desc': 'MySQL database server'},
            5432: {'name': 'PostgreSQL', 'risk': 'critical', 'desc': 'PostgreSQL database server'},
            27017: {'name': 'MongoDB', 'risk': 'critical', 'desc': 'MongoDB database server'},
            6379: {'name': 'Redis', 'risk': 'critical', 'desc': 'Redis in-memory data store'},
            3389: {'name': 'RDP', 'risk': 'high', 'desc': 'Remote Desktop Protocol'},
            5900: {'name': 'VNC', 'risk': 'high', 'desc': 'Virtual Network Computing'},
            8080: {'name': 'HTTP-Alt', 'risk': 'medium', 'desc': 'Alternative HTTP port'},
            9200: {'name': 'Elasticsearch', 'risk': 'high', 'desc': 'Elasticsearch HTTP API'}
        }

        # Load from config if available
        config_port_info = self.analysis_config.get('port_info', {})
        if config_port_info:
            for port_num, info in config_port_info.items():
                try:
                    default_info[int(port_num)] = {
                        'name': info.get('name', f'Port {port_num}'),
                        'risk': info.get('risk_level', 'medium'),
                        'desc': info.get('description', ''),
                        'remediation': info.get('remediation', '')
                    }
                except (ValueError, TypeError):
                    continue

        return default_info

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
            if port in self.unencrypted_protocols:
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
        description = port_data.get('desc', 'High-risk service exposed')

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
        severity = proto_info.get('severity', 'high')

        # Build description with verification info
        verification_note = ""
        if verified_by_tlsx:
            verification_note = " (Verified by tlsx - TLS handshake failed)"
        else:
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
        Get risk level for a port.

        Args:
            port: Port number

        Returns:
            Risk level: critical/high/medium/low/info
        """
        if port in self.database_ports:
            return 'critical'
        elif port in self.high_risk_ports:
            return 'high'
        elif port in self.medium_risk_ports:
            return 'medium'
        elif port in [80, 443]:
            return 'low'
        else:
            return 'info'
