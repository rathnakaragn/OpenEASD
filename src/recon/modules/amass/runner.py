"""
OpenEASD Recon Layer - Amass Runner
6-Layer Architecture - Recon Layer

Amass tool implementation for subdomain discovery.
Handles execution, output parsing, and result standardization.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

from ...interfaces.tool import ReconTool, ReconResult, ToolType, ToolStatus


class AmassRunner(ReconTool):
    """
    Amass tool runner for subdomain discovery.

    Features:
    - Passive and active enumeration
    - JSON output parsing
    - Multiple data source integration
    - Config file support for API keys
    - DNS brute-forcing support
    - Comprehensive subdomain discovery
    """

    def __init__(
        self,
        executable_path: Optional[str] = None,
        default_timeout: int = 900,  # 15 minutes default for Amass
        max_retries: int = 3
    ):
        """
        Initialize Amass runner.

        Args:
            executable_path: Path to amass executable
            default_timeout: Default execution timeout
            max_retries: Maximum retry attempts
        """
        super().__init__(
            tool_name="amass",
            tool_type=ToolType.SUBDOMAIN_DISCOVERY,
            executable_path=executable_path,
            default_timeout=default_timeout,
            max_retries=max_retries
        )

        # Default amass configuration
        self.default_options = {
            "passive": True,  # Passive mode by default (safe)
            "active": False,  # Active enumeration disabled by default
            "brute": False,  # Brute-force disabled by default
            "json_output": True,
            "timeout": 15,  # Minutes
            "max_dns_queries": 0,  # 0 = unlimited
            "include_sources": None,  # Use all sources
            "exclude_sources": None,
            "config": None,  # Path to config file
            "verbose": False
        }

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> ReconResult:
        """
        Execute amass against a target domain.

        Args:
            target: Target domain for subdomain discovery
            options: Amass-specific options
            timeout: Execution timeout in seconds

        Returns:
            ReconResult with discovered subdomains
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
            result.set_error("Amass is not installed or not accessible")
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
            result.set_error("Invalid target domain")
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
                    f"Amass discovered {len(result.assets_discovered)} subdomains for {target}"
                )

            except Exception as e:
                self.logger.error(f"Failed to parse amass output: {e}")
                result.parsed_data = {"parse_error": str(e), "raw_lines": result.raw_output.split('\n')}

        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse amass JSON output into standardized format.

        Args:
            raw_output: Raw amass output

        Returns:
            Parsed data with subdomains and metadata
        """
        parsed_data = {
            "subdomains": [],
            "sources": set(),
            "addresses": {},  # subdomain -> [IP addresses]
            "total_count": 0,
            "unique_count": 0,
            "parsing_errors": []
        }

        if not raw_output.strip():
            return parsed_data

        # Process each line (amass outputs one JSON object per line)
        seen_subdomains = set()

        for line_num, line in enumerate(raw_output.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue

            try:
                # Try to parse as JSON first
                if line.startswith('{'):
                    data = json.loads(line)
                    subdomain = data.get('name', '').strip().lower()

                    if subdomain:
                        # Extract addresses
                        addresses = []
                        if 'addresses' in data:
                            for addr in data.get('addresses', []):
                                if isinstance(addr, dict):
                                    ip = addr.get('ip', '')
                                    if ip:
                                        addresses.append(ip)
                                elif isinstance(addr, str):
                                    addresses.append(addr)

                        # Extract sources
                        sources = data.get('sources', [])
                        if isinstance(sources, str):
                            sources = [sources]

                        parsed_data["subdomains"].append({
                            "subdomain": subdomain,
                            "addresses": addresses,
                            "sources": sources,
                            "domain": data.get('domain', ''),
                            "tag": data.get('tag', ''),
                            "asn": data.get('asn'),
                            "desc": data.get('desc')
                        })

                        seen_subdomains.add(subdomain)
                        if addresses:
                            parsed_data["addresses"][subdomain] = addresses

                        for source in sources:
                            parsed_data["sources"].add(source)

                else:
                    # Handle plain text output (fallback)
                    subdomain = self._extract_subdomain_from_line(line)
                    if subdomain:
                        parsed_data["subdomains"].append({
                            "subdomain": subdomain,
                            "addresses": [],
                            "sources": ["unknown"],
                            "domain": "",
                            "tag": "",
                            "asn": None,
                            "desc": None
                        })
                        seen_subdomains.add(subdomain)

            except json.JSONDecodeError as e:
                # Try to extract subdomain from non-JSON line
                subdomain = self._extract_subdomain_from_line(line)
                if subdomain:
                    parsed_data["subdomains"].append({
                        "subdomain": subdomain,
                        "addresses": [],
                        "sources": ["unknown"],
                        "domain": "",
                        "tag": "",
                        "asn": None,
                        "desc": None
                    })
                    seen_subdomains.add(subdomain)
                else:
                    parsed_data["parsing_errors"].append({
                        "line": line_num,
                        "content": line[:100],  # Limit error content
                        "error": str(e)
                    })

            except Exception as e:
                parsed_data["parsing_errors"].append({
                    "line": line_num,
                    "content": line[:100],
                    "error": str(e)
                })

        # Update counts
        parsed_data["total_count"] = len(parsed_data["subdomains"])
        parsed_data["unique_count"] = len(seen_subdomains)
        parsed_data["sources"] = list(parsed_data["sources"])

        return parsed_data

    def validate_installation(self) -> bool:
        """
        Validate that amass is installed and accessible.

        Returns:
            True if amass is available
        """
        if self._validated:
            return True

        try:
            # Find amass executable
            if not self.executable_path:
                self.executable_path = self._find_executable(['amass'])

            if not self.executable_path:
                self.logger.error("Amass executable not found in PATH")
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
                self.logger.info(f"Amass validated at: {self.executable_path}")
                return True
            else:
                self.logger.error(f"Amass validation failed: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Amass validation error: {e}")
            return False

    def _build_command_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build amass command line arguments.

        Args:
            target: Target domain
            options: Amass options

        Returns:
            List of command arguments
        """
        args = ['enum', '-d', target]

        # JSON output (always enabled for parsing)
        args.append('-json')

        # Passive vs Active mode
        if options.get('passive', True) and not options.get('active', False):
            args.append('-passive')
        elif options.get('active', False):
            args.append('-active')

        # Brute-force enumeration
        if options.get('brute', False):
            args.append('-brute')

        # Verbose output
        if options.get('verbose', False):
            args.append('-v')

        # Timeout settings (in minutes)
        if 'timeout' in options and options['timeout'] > 0:
            args.extend(['-timeout', str(options['timeout'])])

        # Max DNS queries
        if 'max_dns_queries' in options and options['max_dns_queries'] > 0:
            args.extend(['-max-dns-queries', str(options['max_dns_queries'])])

        # Include specific sources
        if options.get('include_sources'):
            sources = options['include_sources']
            if isinstance(sources, list):
                args.extend(['-include', ','.join(sources)])
            elif isinstance(sources, str):
                args.extend(['-include', sources])

        # Exclude specific sources
        if options.get('exclude_sources'):
            exclude = options['exclude_sources']
            if isinstance(exclude, list):
                args.extend(['-exclude', ','.join(exclude)])
            elif isinstance(exclude, str):
                args.extend(['-exclude', exclude])

        # Configuration file
        if options.get('config'):
            args.extend(['-config', options['config']])

        # IP addresses discovery
        if options.get('ip', True):
            args.append('-ip')

        # IPv4 only
        if options.get('ipv4_only', False):
            args.append('-ipv4')

        # IPv6 only
        if options.get('ipv6_only', False):
            args.append('-ipv6')

        # Minimum for subdomain name reuse
        if 'min_for_recursive' in options:
            args.extend(['-min-for-recursive', str(options['min_for_recursive'])])

        return args

    def _extract_assets(self, parsed_data: Dict[str, Any], target_domain: str) -> List[Dict[str, Any]]:
        """
        Extract asset information from parsed amass data.

        Args:
            parsed_data: Parsed amass output
            target_domain: Original target domain

        Returns:
            List of discovered assets
        """
        assets = []

        for subdomain_info in parsed_data.get("subdomains", []):
            subdomain = subdomain_info.get("subdomain")
            if not subdomain:
                continue

            asset = {
                "domain": target_domain,
                "subdomain": subdomain,
                "ip_address": subdomain_info.get("addresses", [None])[0] if subdomain_info.get("addresses") else None,
                "all_addresses": subdomain_info.get("addresses", []),
                "service": "dns",
                "confidence_score": 95,  # Very high confidence for amass results
                "scan_source": "amass",
                "metadata": {
                    "discovery_sources": subdomain_info.get("sources", []),
                    "asn": subdomain_info.get("asn"),
                    "description": subdomain_info.get("desc"),
                    "tag": subdomain_info.get("tag"),
                    "address_count": len(subdomain_info.get("addresses", []))
                }
            }

            # Add tags based on subdomain characteristics
            tags = []

            # Identify common subdomain types
            subdomain_lower = subdomain.lower()
            if any(keyword in subdomain_lower for keyword in ['api', 'rest', 'graphql']):
                tags.append('api')
            if any(keyword in subdomain_lower for keyword in ['admin', 'control', 'manage', 'panel']):
                tags.append('admin')
            if any(keyword in subdomain_lower for keyword in ['dev', 'test', 'staging', 'beta', 'qa']):
                tags.append('development')
            if any(keyword in subdomain_lower for keyword in ['mail', 'smtp', 'imap', 'pop', 'webmail']):
                tags.append('email')
            if any(keyword in subdomain_lower for keyword in ['www', 'web', 'portal', 'app']):
                tags.append('web')
            if any(keyword in subdomain_lower for keyword in ['vpn', 'remote', 'access']):
                tags.append('remote_access')
            if any(keyword in subdomain_lower for keyword in ['prod', 'production']):
                tags.append('production')

            asset["tags"] = tags
            assets.append(asset)

        return assets

    def _extract_subdomain_from_line(self, line: str) -> Optional[str]:
        """
        Extract subdomain from a text line using regex.

        Args:
            line: Text line potentially containing subdomain

        Returns:
            Extracted subdomain or None
        """
        # Match domain patterns
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

        # Clean the line
        line = line.strip()

        # Direct match
        if re.match(domain_pattern, line):
            return line.lower()

        # Try to extract domain from URLs or other formats
        url_pattern = r'https?://([a-zA-Z0-9\-\.]+)'
        match = re.search(url_pattern, line)
        if match:
            domain = match.group(1)
            if re.match(domain_pattern, domain):
                return domain.lower()

        return None

    def _validate_target(self, target: str) -> bool:
        """
        Validate domain target format.

        Args:
            target: Target domain

        Returns:
            True if valid domain format
        """
        if not super()._validate_target(target):
            return False

        # Domain validation regex
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(domain_pattern, target.strip()) is not None

    def _extract_version(self, output: str) -> Optional[str]:
        """
        Extract version from amass output.

        Args:
            output: Version command output

        Returns:
            Version string or None
        """
        # Amass version patterns
        patterns = [
            r'amass\s+v?(\d+\.\d+\.\d+)',
            r'version\s+v?(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)

        return super()._extract_version(output)
