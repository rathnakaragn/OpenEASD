"""
OpenEASD Security Tools Layer

This package contains modules for executing external security tools
and parsing their output. Each tool has its own subpackage with
dedicated runner functions.

Tool Modules:
- subfinder: Passive subdomain discovery
- amass: Comprehensive subdomain enumeration (active/passive)
- dnsx: DNS resolution and record enumeration
- naabu: Fast port scanning
- httpx: HTTP/HTTPS probing
- tlsx: TLS/SSL certificate verification
- nmap: Service detection and vulnerability scanning

Usage:
    # Import from individual modules
    from src.tools.subfinder import run_subfinder
    from src.tools.nmap import run_nmap_service_detection

    # Or import from runners for backward compatibility
    from src.tools.runners import run_subfinder, run_nmap_service_detection
"""

__version__ = "1.0.0"
