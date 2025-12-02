"""
TLSX Tool - TLS/SSL Certificate Scanner

External tool for TLS/SSL verification and certificate analysis.
Install: https://github.com/projectdiscovery/tlsx

Features:
- TLS handshake verification
- Certificate chain validation
- TLS version detection
- Cipher suite enumeration
- Expired/self-signed certificate detection
- JSON output

Used to verify if services have TLS enabled, which helps identify
unencrypted protocols that should be using encryption.
"""

__version__ = "1.0.0"
