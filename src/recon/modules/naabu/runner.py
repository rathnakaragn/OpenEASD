"""
OpenEASD Recon Layer - Naabu Runner
6-Layer Architecture - Recon Layer

Naabu tool implementation for fast port scanning.
Handles execution, JSON output parsing, and result standardization.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import json
import re
import ipaddress
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

from ...interfaces.tool import ReconTool, ReconResult, ToolType, ToolStatus


class NaabuRunner(ReconTool):
    """
    Naabu tool runner for fast port scanning.
    
    Features:
    - JSON output parsing
    - High-speed scanning
    - Top ports configuration
    - Custom port lists
    - Rate limiting
    - Host discovery
    """
    
    def __init__(
        self,
        executable_path: Optional[str] = None,
        default_timeout: int = 900,  # 15 minutes for port scanning
        max_retries: int = 2
    ):
        """
        Initialize Naabu runner.
        
        Args:
            executable_path: Path to naabu executable
            default_timeout: Default execution timeout
            max_retries: Maximum retry attempts
        """
        super().__init__(
            tool_name="naabu",
            tool_type=ToolType.PORT_SCANNING,
            executable_path=executable_path,
            default_timeout=default_timeout,
            max_retries=max_retries
        )
        
        # Default naabu configuration
        self.default_options = {
            "top_ports": 1000,
            "rate": 1000,
            "json_output": True,
            "verify": True,
            "verbose": False,
            "timeout": 5000,  # milliseconds
            "retries": 1
        }

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> ReconResult:
        """
        Execute naabu against a target.
        
        Args:
            target: Target IP, domain, or CIDR range
            options: Naabu-specific options
            timeout: Execution timeout in seconds
            
        Returns:
            ReconResult with discovered open ports
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
            result.set_error("Naabu is not installed or not accessible")
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
            result.set_error("Invalid target address or range")
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
                    f"Naabu discovered {len(result.assets_discovered)} open ports on {target}"
                )
                
            except Exception as e:
                self.logger.error(f"Failed to parse naabu output: {e}")
                result.parsed_data = {"parse_error": str(e)}
                
        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse naabu JSON output into standardized format.
        
        Args:
            raw_output: Raw naabu output
            
        Returns:
            Parsed data with hosts and open ports
        """
        parsed_data = {
            "hosts": {},
            "total_ports": 0,
            "unique_hosts": 0,
            "parsing_errors": []
        }
        
        if not raw_output.strip():
            return parsed_data
        
        # Process each line (naabu outputs one JSON object per line)
        for line_num, line in enumerate(raw_output.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                # Try to parse as JSON
                if line.startswith('{'):
                    data = json.loads(line)
                    
                    host = data.get('host', '').strip()
                    port = data.get('port')
                    protocol = data.get('protocol', 'tcp').lower()
                    
                    if host and port:
                        # Initialize host entry if not exists
                        if host not in parsed_data["hosts"]:
                            parsed_data["hosts"][host] = {
                                "host": host,
                                "ports": [],
                                "port_count": 0
                            }
                        
                        # Add port information
                        port_info = {
                            "port": int(port),
                            "protocol": protocol,
                            "status": "open",
                            "service": data.get('service', 'unknown'),
                            "timestamp": data.get('timestamp'),
                            "ip": data.get('ip', host)
                        }
                        
                        parsed_data["hosts"][host]["ports"].append(port_info)
                        parsed_data["hosts"][host]["port_count"] += 1
                        parsed_data["total_ports"] += 1
                        
                else:
                    # Handle plain text output (fallback)
                    port_info = self._extract_port_from_line(line)
                    if port_info:
                        host = port_info['host']
                        
                        if host not in parsed_data["hosts"]:
                            parsed_data["hosts"][host] = {
                                "host": host,
                                "ports": [],
                                "port_count": 0
                            }
                        
                        parsed_data["hosts"][host]["ports"].append({
                            "port": port_info['port'],
                            "protocol": port_info.get('protocol', 'tcp'),
                            "status": "open",
                            "service": "unknown",
                            "timestamp": None,
                            "ip": host
                        })
                        parsed_data["hosts"][host]["port_count"] += 1
                        parsed_data["total_ports"] += 1
                        
            except json.JSONDecodeError as e:
                # Try to extract port info from non-JSON line
                port_info = self._extract_port_from_line(line)
                if port_info:
                    host = port_info['host']
                    
                    if host not in parsed_data["hosts"]:
                        parsed_data["hosts"][host] = {
                            "host": host,
                            "ports": [],
                            "port_count": 0
                        }
                    
                    parsed_data["hosts"][host]["ports"].append({
                        "port": port_info['port'],
                        "protocol": port_info.get('protocol', 'tcp'),
                        "status": "open",
                        "service": "unknown",
                        "timestamp": None,
                        "ip": host
                    })
                    parsed_data["hosts"][host]["port_count"] += 1
                    parsed_data["total_ports"] += 1
                else:
                    parsed_data["parsing_errors"].append({
                        "line": line_num,
                        "content": line,
                        "error": str(e)
                    })
                    
            except Exception as e:
                parsed_data["parsing_errors"].append({
                    "line": line_num,
                    "content": line,
                    "error": str(e)
                })
        
        # Update unique hosts count
        parsed_data["unique_hosts"] = len(parsed_data["hosts"])
        
        # Convert hosts dict to list for consistency
        parsed_data["hosts"] = list(parsed_data["hosts"].values())
        
        return parsed_data

    def validate_installation(self) -> bool:
        """
        Validate that naabu is installed and accessible.
        
        Returns:
            True if naabu is available
        """
        if self._validated:
            return True
            
        try:
            # Find naabu executable
            if not self.executable_path:
                self.executable_path = self._find_executable(['naabu'])
                
            if not self.executable_path:
                self.logger.error("Naabu executable not found in PATH")
                return False
                
            # Test basic execution
            import subprocess
            result = subprocess.run(
                [self.executable_path, '-h'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self._validated = True
                self.logger.info(f"Naabu validated at: {self.executable_path}")
                return True
            else:
                self.logger.error(f"Naabu validation failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Naabu validation error: {e}")
            return False

    def _build_command_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build naabu command line arguments.
        
        Args:
            target: Target address or range
            options: Naabu options
            
        Returns:
            List of command arguments
        """
        args = []
        
        # Host specification
        args.extend(['-host', target])
        
        # JSON output (always enabled for parsing)
        args.append('-json')
        
        # Verbose output
        if options.get('verbose', False):
            args.append('-v')
            
        # Silent mode (opposite of verbose)
        elif options.get('silent', False):
            args.append('-silent')
            
        # Port specifications
        if 'ports' in options:
            args.extend(['-p', options['ports']])
        elif 'top_ports' in options:
            args.extend(['-top-ports', str(options['top_ports'])])
        elif 'port_file' in options:
            args.extend(['-pf', options['port_file']])
            
        # Exclude ports
        if 'exclude_ports' in options:
            args.extend(['-exclude-ports', options['exclude_ports']])
            
        # Rate limiting
        if 'rate' in options:
            args.extend(['-rate', str(options['rate'])])
            
        # Connection timeout
        if 'timeout' in options:
            args.extend(['-timeout', str(options['timeout'])])
            
        # Retries
        if 'retries' in options:
            args.extend(['-retries', str(options['retries'])])
            
        # Host discovery options
        if options.get('no_probe', False):
            args.append('-Pn')
        elif options.get('ping', False):
            args.append('-ping')
            
        # Verification
        if options.get('verify', True):
            args.append('-verify')
        else:
            args.append('-no-verify')
            
        # Source IP
        if 'source_ip' in options:
            args.extend(['-source-ip', options['source_ip']])
            
        # Interface
        if 'interface' in options:
            args.extend(['-interface', options['interface']])
            
        # Scan type
        if 'scan_type' in options:
            scan_type = options['scan_type']
            if scan_type == 'syn':
                args.append('-syn')
            elif scan_type == 'connect':
                args.append('-c')
                
        # TCP flags
        if 'tcp_flags' in options:
            args.extend(['-tcp-flags', options['tcp_flags']])
            
        # Output file
        if 'output_file' in options:
            args.extend(['-o', options['output_file']])
            
        # Resume scan
        if 'resume' in options:
            args.extend(['-resume', options['resume']])
            
        # Configuration file
        if 'config' in options:
            args.extend(['-config', options['config']])
            
        # Threads
        if 'threads' in options:
            args.extend(['-c', str(options['threads'])])
            
        return args

    def _extract_assets(self, parsed_data: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
        """
        Extract asset information from parsed naabu data.
        
        Args:
            parsed_data: Parsed naabu output
            target: Original target
            
        Returns:
            List of discovered assets
        """
        assets = []
        
        for host_data in parsed_data.get("hosts", []):
            host = host_data.get("host")
            if not host:
                continue
                
            # Determine if host is IP or domain
            is_ip = self._is_ip_address(host)
            
            for port_info in host_data.get("ports", []):
                port = port_info.get("port")
                protocol = port_info.get("protocol", "tcp")
                
                if not port:
                    continue
                
                asset = {
                    "domain": target if not is_ip else host,
                    "ip_address": host if is_ip else port_info.get("ip", host),
                    "port": port,
                    "protocol": protocol,
                    "service": self._guess_service_from_port(port, protocol),
                    "confidence_score": 85,  # Good confidence for naabu results
                    "scan_source": "naabu",
                    "metadata": {
                        "port_status": port_info.get("status", "open"),
                        "discovery_timestamp": port_info.get("timestamp"),
                        "scan_method": "tcp_syn" if protocol == "tcp" else "udp"
                    }
                }
                
                # Add tags based on port and service
                tags = []
                
                # Common service tags based on port
                if port in [80, 8080, 8000, 8443]:
                    tags.append('web')
                elif port in [443, 8443]:
                    tags.extend(['web', 'ssl'])
                elif port in [22]:
                    tags.append('ssh')
                elif port in [21]:
                    tags.append('ftp')
                elif port in [23]:
                    tags.append('telnet')
                elif port in [25, 587]:
                    tags.append('smtp')
                elif port in [53]:
                    tags.append('dns')
                elif port in [110]:
                    tags.append('pop3')
                elif port in [143]:
                    tags.append('imap')
                elif port in [3389]:
                    tags.append('rdp')
                elif port in [3306]:
                    tags.append('mysql')
                elif port in [5432]:
                    tags.append('postgresql')
                elif port in [1433]:
                    tags.append('mssql')
                elif port in [5984]:
                    tags.append('couchdb')
                elif port in [6379]:
                    tags.append('redis')
                elif port in [9200]:
                    tags.append('elasticsearch')
                elif port in [27017]:
                    tags.append('mongodb')
                    
                # Security tags
                if port in [23, 21, 80, 110, 143] and protocol == 'tcp':
                    tags.append('unencrypted')
                if port in [22, 3389, 23, 21]:
                    tags.append('remote-access')
                if port in [3306, 5432, 1433, 6379, 27017]:
                    tags.append('database')
                    
                asset["tags"] = list(set(tags))  # Remove duplicates
                assets.append(asset)
        
        return assets

    def _extract_port_from_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Extract port information from a text line using regex.
        
        Args:
            line: Text line potentially containing port info
            
        Returns:
            Extracted port information or None
        """
        # Common patterns for port information
        patterns = [
            r'(\S+):(\d+)/(tcp|udp)',  # host:port/protocol
            r'(\S+):(\d+)',            # host:port
            r'(\d+)/(tcp|udp)\s+open\s+(\S+)',  # port/protocol open service
            r'(\d+)\s+(tcp|udp)\s+(\S+)',  # port protocol service
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                if ':' in pattern:  # host:port format
                    return {
                        "host": match.group(1),
                        "port": int(match.group(2)),
                        "protocol": match.group(3) if len(match.groups()) > 2 else "tcp"
                    }
                else:  # port only format
                    return {
                        "host": "unknown",
                        "port": int(match.group(1)),
                        "protocol": match.group(2) if len(match.groups()) > 1 else "tcp"
                    }
                    
        return None

    def _guess_service_from_port(self, port: int, protocol: str = "tcp") -> str:
        """
        Guess service name based on port number and protocol.
        
        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Guessed service name
        """
        # Common port-to-service mappings
        tcp_services = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
            587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
            1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5984: "couchdb", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
            9200: "elasticsearch", 27017: "mongodb"
        }
        
        udp_services = {
            53: "dns", 67: "dhcps", 68: "dhcpc", 69: "tftp", 123: "ntp",
            161: "snmp", 162: "snmptrap", 514: "syslog"
        }
        
        if protocol.lower() == "tcp":
            return tcp_services.get(port, "unknown")
        elif protocol.lower() == "udp":
            return udp_services.get(port, "unknown")
        else:
            return "unknown"

    def _is_ip_address(self, addr: str) -> bool:
        """
        Check if string is an IP address.
        
        Args:
            addr: Address string
            
        Returns:
            True if valid IP address
        """
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    def _validate_target(self, target: str) -> bool:
        """
        Validate naabu target format (IP, domain, or CIDR).
        
        Args:
            target: Target specification
            
        Returns:
            True if valid target format
        """
        if not super()._validate_target(target):
            return False
            
        target = target.strip()
        
        try:
            # Try to parse as IP address or CIDR
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
            
        # Validate as domain name
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, target):
            return True
            
        # Allow hostname without domain
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if re.match(hostname_pattern, target):
            return True
            
        return False

    def _extract_version(self, output: str) -> Optional[str]:
        """
        Extract version from naabu output.
        
        Args:
            output: Version command output
            
        Returns:
            Version string or None
        """
        # Naabu version patterns
        patterns = [
            r'naabu\s+v?(\d+\.\d+\.\d+)',
            r'Current\s+Version:\s+v?(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return super()._extract_version(output)