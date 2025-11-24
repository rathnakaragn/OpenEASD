"""
dnsx Tool - Fast DNS Toolkit

External tool for DNS resolution and record enumeration.
Install: https://github.com/projectdiscovery/dnsx

Features:
- Fast DNS resolution
- Multiple record type queries (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV)
- JSON output support
- Bulk domain processing
- Response data extraction

Usage in CLI:
    openeasd run dnsx example.com
    openeasd run dnsx example.com --records a --records mx
    openeasd run dnsx api.example.com www.example.com -r ns -r txt
"""

__version__ = "1.0.0"
