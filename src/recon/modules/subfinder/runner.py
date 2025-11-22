"""
OpenEASD Recon Layer - Subfinder Runner
6-Layer Architecture - Recon Layer

Subfinder tool implementation for subdomain discovery.
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


class SubfinderRunner(ReconTool):
    """
    Subfinder tool runner for subdomain discovery.
    
    Features:
    - JSON output parsing
    - Passive and active enumeration
    - Custom source configuration
    - Rate limiting support
    - Recursive subdomain discovery
    """
    
    def __init__(
        self,
        executable_path: Optional[str] = None,
        default_timeout: int = 600,
        max_retries: int = 3
    ):
        """
        Initialize Subfinder runner.
        
        Args:
            executable_path: Path to subfinder executable
            default_timeout: Default execution timeout
            max_retries: Maximum retry attempts
        """
        super().__init__(
            tool_name="subfinder",
            tool_type=ToolType.SUBDOMAIN_DISCOVERY,
            executable_path=executable_path,
            default_timeout=default_timeout,
            max_retries=max_retries
        )
        
        # Default subfinder configuration
        self.default_options = {
            "all_sources": True,
            "active": False,
            "json_output": True,
            "verbose": False,
            "timeout": 30,
            "max_time": 10,
            "threads": 10
        }

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> ReconResult:
        """
        Execute subfinder against a target domain.
        
        Args:
            target: Target domain for subdomain discovery
            options: Subfinder-specific options
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
            result.set_error("Subfinder is not installed or not accessible")
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
                    f"Subfinder discovered {len(result.assets_discovered)} subdomains for {target}"
                )
                
            except Exception as e:
                self.logger.error(f"Failed to parse subfinder output: {e}")
                result.parsed_data = {"parse_error": str(e), "raw_lines": result.raw_output.split('\n')}
                
        return result

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse subfinder JSON output into standardized format.
        
        Args:
            raw_output: Raw subfinder output
            
        Returns:
            Parsed data with subdomains and metadata
        """
        parsed_data = {
            "subdomains": [],
            "sources": set(),
            "total_count": 0,
            "unique_count": 0,
            "parsing_errors": []
        }
        
        if not raw_output.strip():
            return parsed_data
        
        # Process each line (subfinder outputs one JSON object per line)
        seen_subdomains = set()
        
        for line_num, line in enumerate(raw_output.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                # Try to parse as JSON first
                if line.startswith('{'):
                    data = json.loads(line)
                    subdomain = data.get('host', '').strip().lower()
                    source = data.get('source', 'unknown')
                    
                    if subdomain:
                        parsed_data["subdomains"].append({
                            "subdomain": subdomain,
                            "source": source,
                            "ip": data.get('ip'),
                            "response_code": data.get('status_code'),
                            "title": data.get('title'),
                            "content_length": data.get('content_length')
                        })
                        
                        seen_subdomains.add(subdomain)
                        parsed_data["sources"].add(source)
                        
                else:
                    # Handle plain text output (fallback)
                    subdomain = self._extract_subdomain_from_line(line)
                    if subdomain:
                        parsed_data["subdomains"].append({
                            "subdomain": subdomain,
                            "source": "unknown",
                            "ip": None,
                            "response_code": None,
                            "title": None,
                            "content_length": None
                        })
                        seen_subdomains.add(subdomain)
                        
            except json.JSONDecodeError as e:
                # Try to extract subdomain from non-JSON line
                subdomain = self._extract_subdomain_from_line(line)
                if subdomain:
                    parsed_data["subdomains"].append({
                        "subdomain": subdomain,
                        "source": "unknown",
                        "ip": None,
                        "response_code": None,
                        "title": None,
                        "content_length": None
                    })
                    seen_subdomains.add(subdomain)
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
        
        # Update counts
        parsed_data["total_count"] = len(parsed_data["subdomains"])
        parsed_data["unique_count"] = len(seen_subdomains)
        parsed_data["sources"] = list(parsed_data["sources"])
        
        return parsed_data

    def validate_installation(self) -> bool:
        """
        Validate that subfinder is installed and accessible.
        
        Returns:
            True if subfinder is available
        """
        if self._validated:
            return True
            
        try:
            # Find subfinder executable
            if not self.executable_path:
                self.executable_path = self._find_executable(['subfinder'])
                
            if not self.executable_path:
                self.logger.error("Subfinder executable not found in PATH")
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
                self.logger.info(f"Subfinder validated at: {self.executable_path}")
                return True
            else:
                self.logger.error(f"Subfinder validation failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Subfinder validation error: {e}")
            return False

    def _build_command_args(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build subfinder command line arguments.
        
        Args:
            target: Target domain
            options: Subfinder options
            
        Returns:
            List of command arguments
        """
        args = ['-d', target]
        
        # JSON output (always enabled for parsing)
        args.extend(['-o', '/dev/stdout', '-json'])
        
        # Source configuration
        if options.get('all_sources', True):
            args.append('-all')
            
        # Active enumeration
        if options.get('active', False):
            args.append('-active')
            
        # Verbose output
        if options.get('verbose', False):
            args.append('-v')
            
        # Timeout settings
        if 'timeout' in options:
            args.extend(['-timeout', str(options['timeout'])])
            
        if 'max_time' in options:
            args.extend(['-max-time', str(options['max_time'])])
            
        # Threading
        if 'threads' in options:
            args.extend(['-t', str(options['threads'])])
            
        # Rate limiting
        if 'rate_limit' in options:
            args.extend(['-rate-limit', str(options['rate_limit'])])
            
        # Recursive enumeration
        if options.get('recursive', False):
            args.append('-recursive')
            
        # Sources to use
        if 'sources' in options:
            sources = options['sources']
            if isinstance(sources, list):
                args.extend(['-sources', ','.join(sources)])
            elif isinstance(sources, str):
                args.extend(['-sources', sources])
                
        # Sources to exclude
        if 'exclude_sources' in options:
            exclude = options['exclude_sources']
            if isinstance(exclude, list):
                args.extend(['-exclude-sources', ','.join(exclude)])
            elif isinstance(exclude, str):
                args.extend(['-exclude-sources', exclude])
                
        # Configuration file
        if 'config' in options:
            args.extend(['-config', options['config']])
            
        # Proxy settings
        if 'proxy' in options:
            args.extend(['-proxy', options['proxy']])
            
        return args

    def _extract_assets(self, parsed_data: Dict[str, Any], target_domain: str) -> List[Dict[str, Any]]:
        """
        Extract asset information from parsed subfinder data.
        
        Args:
            parsed_data: Parsed subfinder output
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
                "ip_address": subdomain_info.get("ip"),
                "service": "dns",
                "confidence_score": 90,  # High confidence for subfinder results
                "scan_source": "subfinder",
                "metadata": {
                    "discovery_source": subdomain_info.get("source", "unknown"),
                    "response_code": subdomain_info.get("response_code"),
                    "title": subdomain_info.get("title"),
                    "content_length": subdomain_info.get("content_length"),
                    "discovery_method": "passive_dns" if not subdomain_info.get("active") else "active_dns"
                }
            }
            
            # Add tags based on subdomain characteristics
            tags = []
            
            # Identify common subdomain types
            subdomain_lower = subdomain.lower()
            if any(keyword in subdomain_lower for keyword in ['api', 'rest', 'graphql']):
                tags.append('api')
            if any(keyword in subdomain_lower for keyword in ['admin', 'control', 'manage']):
                tags.append('admin')
            if any(keyword in subdomain_lower for keyword in ['dev', 'test', 'staging', 'beta']):
                tags.append('development')
            if any(keyword in subdomain_lower for keyword in ['mail', 'smtp', 'imap', 'pop']):
                tags.append('email')
            if any(keyword in subdomain_lower for keyword in ['www', 'web', 'portal']):
                tags.append('web')
                
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
        Extract version from subfinder output.
        
        Args:
            output: Version command output
            
        Returns:
            Version string or None
        """
        # Subfinder version patterns
        patterns = [
            r'subfinder\s+v?(\d+\.\d+\.\d+)',
            r'Current\s+Version:\s+v?(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return super()._extract_version(output)