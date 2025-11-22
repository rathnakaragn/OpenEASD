"""
OpenEASD Recon Layer - Nmap Runner
6-Layer Architecture - Recon Layer

Nmap tool implementation for service detection and port scanning.
Handles execution, output parsing, and result standardization.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

from ...interfaces.tool import ReconTool, ReconResult, ToolType, ToolStatus


class NmapRunner(ReconTool):
    """
    Nmap tool runner for service detection and port scanning.

    Features:
    - Service version detection
    - XML output parsing
    - OS detection
    - Script scanning (NSE)
    - Multiple scan types
    - Port range configuration
    """

    def __init__(
        self,
        executable_path: Optional[str] = None,
        default_timeout: int = 1800,  # 30 minutes default for Nmap
        max_retries: int = 3
    ):
        """
        Initialize Nmap runner.

        Args:
            executable_path: Path to nmap executable
            default_timeout: Default execution timeout
            max_retries: Maximum retry attempts
        """
        super().__init__(
            tool_name="nmap",
            tool_type=ToolType.SERVICE_DETECTION,
            executable_path=executable_path,
            default_timeout=default_timeout,
            max_retries=max_retries
        )

        # Default nmap configuration
        self.default_options = {
            "scan_type": "sV",  # Service version detection
            "ports": None,  # None = default ports, or specify like "80,443,8080" or "1-65535"
            "top_ports": 1000,  # Scan top N ports
            "service_detection": True,
            "os_detection": False,
            "script_scan": False,
            "aggressive": False,  # -A flag
            "timing": "3",  # T3 = normal
            "max_retries": 1,
            "host_timeout": "30m",
            "min_rate": None,
            "max_rate": None,
            "verbose": False
        }

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> ReconResult:
        """
        Execute nmap against a target.

        Args:
            target: Target host/IP for scanning
            options: Nmap-specific options
            timeout: Execution timeout in seconds

        Returns:
            ReconResult with discovered services
        """
        # Validate tool installation
        if not self.validate_installation():
            result = ReconResult(
                tool_name=self.tool_name,
                tool_version=await self.get_tool_version(),
                target=target,
                status=ToolStatus.FAILED,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow()
            )
            result.set_error("Nmap is not installed or not accessible")
            return result

        # Validate and sanitize target
        if not self._validate_target(target):
            result = ReconResult(
                tool_name=self.tool_name,
                tool_version=await self.get_tool_version(),
                target=target,
                status=ToolStatus.FAILED,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow()
            )
            result.set_error("Invalid target host/IP")
            return result

        target = self._sanitize_target(target)

        # Merge options with defaults
        run_options = {**self.default_options, **(options or {})}

        # Build command arguments
        args = self._build_command_args(target, run_options)

        # Execute command
        result = await self._execute_command(args, target, timeout)

        # Parse output if successful
        if result.status == ToolStatus.COMPLETED and result.raw_output:
            try:
                parsed_data = self.parse_output(result.raw_output)
                result.parsed_data = parsed_data

                # Extract discovered assets
                result.assets_discovered = self._extract_assets(parsed_data, target)

                self.logger.info(
                    f"Nmap discovered {len(result.assets_discovered)} services for {target}"
                )

            except Exception as e:
                self.logger.error(f"Failed to parse nmap output: {e}")
                result.parsed_data = {"parse_error": str(e), "raw_output": result.raw_output[:1000]}

        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse nmap XML output into standardized format.

        Args:
            raw_output: Raw nmap XML output

        Returns:
            Parsed data with services and metadata
        """
        parsed_data = {
            "hosts": [],
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports": 0,
            "open_ports": 0,
            "services": [],
            "os_matches": [],
            "scan_info": {},
            "parsing_errors": []
        }

        if not raw_output.strip():
            return parsed_data

        try:
            # Parse XML
            root = ET.fromstring(raw_output)

            # Extract scan info
            scan_info = root.find('scaninfo')
            if scan_info is not None:
                parsed_data["scan_info"] = {
                    "type": scan_info.get('type'),
                    "protocol": scan_info.get('protocol'),
                    "numservices": scan_info.get('numservices'),
                    "services": scan_info.get('services')
                }

            # Extract run stats
            runstats = root.find('runstats')
            if runstats is not None:
                hosts_elem = runstats.find('hosts')
                if hosts_elem is not None:
                    parsed_data["total_hosts"] = int(hosts_elem.get('total', 0))
                    parsed_data["hosts_up"] = int(hosts_elem.get('up', 0))
                    parsed_data["hosts_down"] = int(hosts_elem.get('down', 0))

            # Process each host
            for host in root.findall('host'):
                host_data = self._parse_host(host)
                if host_data:
                    parsed_data["hosts"].append(host_data)

                    # Aggregate services
                    for port_info in host_data.get("ports", []):
                        if port_info.get("state") == "open":
                            parsed_data["open_ports"] += 1
                        parsed_data["total_ports"] += 1

                        service_data = {
                            "host": host_data.get("address"),
                            "hostname": host_data.get("hostnames", [None])[0],
                            "port": port_info.get("port"),
                            "protocol": port_info.get("protocol"),
                            "state": port_info.get("state"),
                            "service": port_info.get("service"),
                            "product": port_info.get("product"),
                            "version": port_info.get("version"),
                            "extrainfo": port_info.get("extrainfo"),
                            "cpe": port_info.get("cpe"),
                            "scripts": port_info.get("scripts", [])
                        }
                        parsed_data["services"].append(service_data)

                    # Aggregate OS detection
                    if host_data.get("os_matches"):
                        parsed_data["os_matches"].extend(host_data["os_matches"])

        except ET.ParseError as e:
            parsed_data["parsing_errors"].append({
                "type": "XML Parse Error",
                "error": str(e)
            })
            self.logger.error(f"Failed to parse Nmap XML output: {e}")

        except Exception as e:
            parsed_data["parsing_errors"].append({
                "type": "General Error",
                "error": str(e)
            })
            self.logger.error(f"Unexpected error parsing Nmap output: {e}")

        return parsed_data

    def _parse_host(self, host_elem: ET.Element) -> Dict[str, Any]:
        """
        Parse individual host element from Nmap XML.

        Args:
            host_elem: XML element for host

        Returns:
            Parsed host data
        """
        host_data = {
            "status": {},
            "address": None,
            "hostnames": [],
            "ports": [],
            "os_matches": [],
            "uptime": None
        }

        # Status
        status = host_elem.find('status')
        if status is not None:
            host_data["status"] = {
                "state": status.get('state'),
                "reason": status.get('reason')
            }

        # Address
        address = host_elem.find('address')
        if address is not None:
            host_data["address"] = address.get('addr')
            host_data["address_type"] = address.get('addrtype')

        # Hostnames
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data["hostnames"].append({
                    "name": hostname.get('name'),
                    "type": hostname.get('type')
                })

        # Ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data["ports"].append(port_data)

        # OS detection
        os_elem = host_elem.find('os')
        if os_elem is not None:
            for osmatch in os_elem.findall('osmatch'):
                host_data["os_matches"].append({
                    "name": osmatch.get('name'),
                    "accuracy": osmatch.get('accuracy'),
                    "line": osmatch.get('line')
                })

        # Uptime
        uptime = host_elem.find('uptime')
        if uptime is not None:
            host_data["uptime"] = {
                "seconds": uptime.get('seconds'),
                "lastboot": uptime.get('lastboot')
            }

        return host_data

    def _parse_port(self, port_elem: ET.Element) -> Dict[str, Any]:
        """
        Parse individual port element from Nmap XML.

        Args:
            port_elem: XML element for port

        Returns:
            Parsed port data
        """
        port_data = {
            "port": port_elem.get('portid'),
            "protocol": port_elem.get('protocol'),
            "state": None,
            "service": None,
            "product": None,
            "version": None,
            "extrainfo": None,
            "cpe": [],
            "scripts": []
        }

        # State
        state = port_elem.find('state')
        if state is not None:
            port_data["state"] = state.get('state')
            port_data["reason"] = state.get('reason')

        # Service
        service = port_elem.find('service')
        if service is not None:
            port_data["service"] = service.get('name')
            port_data["product"] = service.get('product')
            port_data["version"] = service.get('version')
            port_data["extrainfo"] = service.get('extrainfo')
            port_data["ostype"] = service.get('ostype')
            port_data["method"] = service.get('method')
            port_data["conf"] = service.get('conf')

            # CPE (Common Platform Enumeration)
            for cpe in service.findall('cpe'):
                port_data["cpe"].append(cpe.text)

        # Scripts
        for script in port_elem.findall('script'):
            port_data["scripts"].append({
                "id": script.get('id'),
                "output": script.get('output')
            })

        return port_data

    def validate_installation(self) -> bool:
        """
        Validate that nmap is installed and accessible.

        Returns:
            True if nmap is available
        """
        if self._validated:
            return True

        try:
            # Find nmap executable
            if not self.executable_path:
                self.executable_path = self._find_executable(['nmap'])

            if not self.executable_path:
                self.logger.error("Nmap executable not found in PATH")
                return False

            # Test basic execution
            import subprocess
            result = subprocess.run(
                [self.executable_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self._validated = True
                self.logger.info(f"Nmap validated at: {self.executable_path}")
                return True
            else:
                self.logger.error(f"Nmap validation failed: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Nmap validation error: {e}")
            return False

    def _build_command_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build nmap command line arguments.

        Args:
            target: Target host/IP
            options: Nmap options

        Returns:
            List of command arguments
        """
        args = []

        # Scan type
        scan_type = options.get('scan_type', 'sV')
        if scan_type:
            args.append(f'-{scan_type}')

        # Service version detection
        if options.get('service_detection', True) and 'V' not in scan_type:
            args.append('-sV')

        # OS detection
        if options.get('os_detection', False):
            args.append('-O')

        # Script scanning
        if options.get('script_scan', False):
            args.append('-sC')

        # Aggressive scan (-A = OS detection, version detection, script scanning, traceroute)
        if options.get('aggressive', False):
            args.append('-A')

        # Port specification
        if options.get('ports'):
            args.extend(['-p', str(options['ports'])])
        elif options.get('top_ports'):
            args.extend(['--top-ports', str(options['top_ports'])])

        # Timing template
        if 'timing' in options:
            args.append(f'-T{options["timing"]}')

        # Verbose
        if options.get('verbose', False):
            args.append('-v')

        # Max retries
        if 'max_retries' in options:
            args.extend(['--max-retries', str(options['max_retries'])])

        # Host timeout
        if 'host_timeout' in options:
            args.extend(['--host-timeout', options['host_timeout']])

        # Rate limiting
        if options.get('min_rate'):
            args.extend(['--min-rate', str(options['min_rate'])])
        if options.get('max_rate'):
            args.extend(['--max-rate', str(options['max_rate'])])

        # DNS resolution
        if options.get('no_dns', False):
            args.append('-n')

        # Randomize hosts
        if options.get('randomize_hosts', False):
            args.append('--randomize-hosts')

        # XML output (always enabled for parsing)
        args.append('-oX')
        args.append('-')  # Output to stdout

        # Target
        args.append(target)

        return args

    def _extract_assets(self, parsed_data: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
        """
        Extract asset information from parsed nmap data.

        Args:
            parsed_data: Parsed nmap output
            target: Original target

        Returns:
            List of discovered assets
        """
        assets = []

        for service in parsed_data.get("services", []):
            if not service.get("port"):
                continue

            # Build service description
            service_name = service.get("service", "unknown")
            product = service.get("product", "")
            version = service.get("version", "")

            service_desc = service_name
            if product:
                service_desc += f" ({product}"
                if version:
                    service_desc += f" {version}"
                service_desc += ")"

            asset = {
                "domain": target,
                "subdomain": service.get("hostname") or service.get("host"),
                "ip_address": service.get("host"),
                "port": int(service.get("port", 0)),
                "protocol": service.get("protocol", "tcp"),
                "service": service_desc,
                "confidence_score": 90,  # High confidence for nmap results
                "scan_source": "nmap",
                "metadata": {
                    "state": service.get("state"),
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": service.get("extrainfo"),
                    "cpe": service.get("cpe", []),
                    "scripts": service.get("scripts", [])
                }
            }

            # Add tags based on service type
            tags = []

            if service.get("state") == "open":
                tags.append('open_port')

            # Service-specific tags
            if service_name in ['http', 'https', 'http-proxy']:
                tags.append('web')
            if service_name in ['ssh']:
                tags.append('remote_access')
            if service_name in ['smtp', 'pop3', 'imap']:
                tags.append('email')
            if service_name in ['mysql', 'postgresql', 'mongodb', 'redis']:
                tags.append('database')
            if service_name in ['ftp', 'sftp']:
                tags.append('file_transfer')
            if service_name in ['dns']:
                tags.append('dns')
            if service_name in ['ldap', 'ldaps']:
                tags.append('directory')

            asset["tags"] = tags
            assets.append(asset)

        return assets

    def _validate_target(self, target: str) -> bool:
        """
        Validate target format (IP, hostname, or CIDR).

        Args:
            target: Target to validate

        Returns:
            True if valid target
        """
        if not super()._validate_target(target):
            return False

        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        # CIDR pattern
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'

        # Domain pattern
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

        target = target.strip()

        return (
            re.match(ip_pattern, target) or
            re.match(cidr_pattern, target) or
            re.match(domain_pattern, target)
        )

    def _extract_version(self, output: str) -> Optional[str]:
        """
        Extract version from nmap output.

        Args:
            output: Version command output

        Returns:
            Version string or None
        """
        # Nmap version patterns
        patterns = [
            r'Nmap\s+version\s+(\d+\.\d+)',
            r'Nmap\s+(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)

        return super()._extract_version(output)
