"""
Tool runner functions for OpenEASD.

This module re-exports functions from individual tool modules for backward compatibility.
Each tool has its own module under src/tools/{tool}/ with the actual implementation.

Tool modules:
- subfinder: Passive subdomain discovery
- amass: Comprehensive subdomain enumeration
- dnsx: DNS resolution and record enumeration
- naabu: Fast port scanning
- httpx: HTTP/HTTPS probing
- tlsx: TLS/SSL certificate verification
- nmap: Service detection and vulnerability scanning
"""

# Re-export from subfinder module
from src.tools.subfinder import run_subfinder

# Re-export from amass module
from src.tools.amass import run_amass, run_amass_intel

# Re-export from dnsx module
from src.tools.dnsx import run_dnsx

# Re-export from naabu module
from src.tools.naabu import run_naabu

# Re-export from httpx module
from src.tools.httpx import run_httpx

# Re-export from tlsx module
from src.tools.tlsx import run_tlsx, run_tlsx_parallel

# Re-export from nmap module
from src.tools.nmap import (
    run_nmap_service_detection,
    run_nmap_service_detection_parallel,
    run_nmap_vuln_detection,
    run_nmap_vuln_detection_parallel,
    _parse_nmap_xml,
    _extract_cves_from_nmap_output,
)

__all__ = [
    # Subfinder
    'run_subfinder',
    # Amass
    'run_amass',
    'run_amass_intel',
    # Dnsx
    'run_dnsx',
    # Naabu
    'run_naabu',
    # Httpx
    'run_httpx',
    # Tlsx
    'run_tlsx',
    'run_tlsx_parallel',
    # Nmap
    'run_nmap_service_detection',
    'run_nmap_service_detection_parallel',
    'run_nmap_vuln_detection',
    'run_nmap_vuln_detection_parallel',
    '_parse_nmap_xml',
    '_extract_cves_from_nmap_output',
]
