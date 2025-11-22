"""
Simplified Scanner implementation for OpenEASD.

Focused on subdomain enumeration and port scanning only.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import json

from src.core.interfaces.scanner import SecurityScanner

logger = logging.getLogger(__name__)


class MVPScanner(SecurityScanner):
    """Simplified implementation of SecurityScanner for subdomain enumeration and port scanning."""

    def __init__(self):
        """Initialize simplified scanner."""
        self.active_scans = {}
        self.supported_scan_types = ["subdomain_port_scan"]

    async def scan_domains(self, domains: List[str], scan_type: str = "subdomain_port_scan") -> List[Dict[str, Any]]:
        """
        Execute security scan on domains using subfinder and naabu.

        Args:
            domains: List of domains to scan
            scan_type: Type of scan - only "subdomain_port_scan" supported

        Returns:
            List of discovered assets (subdomains and ports)
        """
        logger.info(f"Starting subdomain enumeration and port scanning for domains: {', '.join(domains)}")

        scan_id = str(uuid.uuid4())
        self.active_scans[scan_id] = {
            'domains': domains,
            'scan_type': scan_type,
            'status': 'running',
            'started_at': datetime.utcnow(),
            'current_phase': 'initialization',
            'completed_phases': 0
        }

        all_assets = []

        try:
            # Phase 1: Subdomain Discovery
            self._update_scan_progress(scan_id, 'subdomain_discovery', 0, 0)
            all_subdomains = []

            for domain in domains:
                subdomains = await self._discover_subdomains(domain)
                all_subdomains.extend(subdomains)

                # Store subdomain assets
                for subdomain in subdomains:
                    asset = {
                        'id': str(uuid.uuid4()),
                        'domain': domain,
                        'asset_type': 'subdomain',
                        'subdomain': subdomain,
                        'tool_source': 'subfinder',
                        'discovered_at': datetime.utcnow()
                    }
                    all_assets.append(asset)

            self._update_scan_progress(scan_id, 'subdomain_discovery', len(domains), 1)
            logger.info(f"Discovered {len(all_subdomains)} subdomains")

            # Phase 2: Port Scanning
            self._update_scan_progress(scan_id, 'port_scanning', 0, 1)

            # Scan ports on all discovered subdomains plus original domains
            targets = list(set(domains + all_subdomains))

            for target in targets:
                open_ports = await self._scan_ports(target)

                # Store port assets
                for port_info in open_ports:
                    asset = {
                        'id': str(uuid.uuid4()),
                        'domain': target,
                        'asset_type': 'port',
                        'subdomain': target if target not in domains else None,
                        'port': port_info['port'],
                        'protocol': port_info.get('protocol', 'tcp'),
                        'ip_address': port_info.get('ip'),
                        'tool_source': 'naabu',
                        'discovered_at': datetime.utcnow()
                    }
                    all_assets.append(asset)

            self._update_scan_progress(scan_id, 'port_scanning', len(targets), 2)
            logger.info(f"Discovered {sum(1 for a in all_assets if a['asset_type'] == 'port')} open ports")

            # Mark scan as complete
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['completed_at'] = datetime.utcnow()

            logger.info(f"Scan {scan_id} completed. Found {len(all_assets)} assets")
            return all_assets

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)
            return []

    async def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using subfinder."""
        try:
            # Use subprocess to run subfinder
            result = await asyncio.create_subprocess_exec(
                'subfinder', '-d', domain, '-silent', '-json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0 and stdout:
                subdomains = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            if 'host' in data:
                                subdomains.append(data['host'])
                        except json.JSONDecodeError:
                            continue
                return subdomains
        except FileNotFoundError:
            logger.warning("subfinder not found, skipping subdomain discovery")
        except Exception as e:
            logger.error(f"Subdomain discovery failed for {domain}: {e}")

        return []

    async def _scan_ports(self, target: str) -> List[Dict[str, Any]]:
        """Scan ports using naabu."""
        try:
            # Use naabu for port scanning
            result = await asyncio.create_subprocess_exec(
                'naabu', '-host', target, '-top-ports', '1000', '-json', '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0 and stdout:
                ports = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            port_info = {
                                'port': data.get('port'),
                                'protocol': data.get('protocol', 'tcp'),
                                'ip': data.get('ip')
                            }
                            if port_info['port']:
                                ports.append(port_info)
                        except json.JSONDecodeError:
                            continue
                return ports
        except FileNotFoundError:
            logger.warning(f"naabu not found, skipping port scanning for {target}")
        except Exception as e:
            logger.error(f"Port scanning failed for {target}: {e}")

        return []

    async def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get progress information for an ongoing scan."""
        if scan_id not in self.active_scans:
            return None

        scan_info = self.active_scans[scan_id]
        total_phases = 2  # subdomain discovery + port scanning
        completed_phases = scan_info.get('completed_phases', 0)

        progress = {
            'scan_id': scan_id,
            'status': scan_info.get('status', 'unknown'),
            'current_phase': scan_info.get('current_phase', 'starting'),
            'completed_domains': scan_info.get('completed_domains', 0),
            'total_domains': len(scan_info.get('domains', [])),
            'percent_complete': min(int((completed_phases / total_phases) * 100), 100)
        }

        return progress

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an ongoing scan."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'cancelled'
            return True
        return False

    def get_supported_scan_types(self) -> List[str]:
        """Get list of supported scan types."""
        return self.supported_scan_types.copy()

    def _update_scan_progress(self, scan_id: str, phase: str, completed_domains: int = 0, completed_phases: int = 0):
        """Update scan progress (internal method)."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].update({
                'current_phase': phase,
                'completed_domains': completed_domains,
                'completed_phases': completed_phases
            })
