"""
Domain utility functions for OpenEASD.

Provides reusable functions for domain extraction and manipulation
used across service and API layers.
"""

from typing import Dict, Any, Optional, Tuple


def extract_primary_domain(scan_data: Dict[str, Any]) -> str:
    """
    Extract primary domain from scan data.

    Tries multiple fields to find the domain:
    1. 'domain' field
    2. First item in 'domains_scanned' list
    3. Falls back to 'unknown'

    Args:
        scan_data: Dictionary containing scan information

    Returns:
        Primary domain string, or 'unknown' if not found

    Example:
        >>> extract_primary_domain({'domain': 'example.com'})
        'example.com'
        >>> extract_primary_domain({'domains_scanned': ['a.com', 'b.com']})
        'a.com'
        >>> extract_primary_domain({})
        'unknown'
    """
    # Try direct domain field first
    if scan_data.get('domain'):
        return scan_data['domain']

    # Try domains_scanned list
    domains = scan_data.get('domains_scanned', [])
    if domains:
        return domains[0]

    return 'unknown'


def extract_host_from_port_info(port_info: Dict[str, Any]) -> str:
    """
    Extract hostname from port_info dictionary.

    Tries 'subdomain' first, then 'host', then empty string.

    Args:
        port_info: Dictionary containing port information

    Returns:
        Hostname string

    Example:
        >>> extract_host_from_port_info({'subdomain': 'api.example.com'})
        'api.example.com'
        >>> extract_host_from_port_info({'host': '192.168.1.1'})
        '192.168.1.1'
    """
    return port_info.get('subdomain') or port_info.get('host') or ''


def make_port_key(host: str, port: int) -> str:
    """
    Create a unique key for host:port combination.

    Args:
        host: Hostname or IP address
        port: Port number

    Returns:
        String in format "host:port"

    Example:
        >>> make_port_key('example.com', 443)
        'example.com:443'
    """
    return f"{host}:{port}"


def parse_port_key(port_key: str) -> Tuple[str, int]:
    """
    Parse a host:port key into components.

    Args:
        port_key: String in format "host:port"

    Returns:
        Tuple of (host, port)

    Raises:
        ValueError: If port_key is not in valid format

    Example:
        >>> parse_port_key('example.com:443')
        ('example.com', 443)
    """
    parts = port_key.rsplit(':', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid port key format: {port_key}")
    return parts[0], int(parts[1])


__all__ = [
    'extract_primary_domain',
    'extract_host_from_port_info',
    'make_port_key',
    'parse_port_key',
]
