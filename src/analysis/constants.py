"""
Analysis layer constants for OpenEASD.

Defines port classifications, risk mappings, and detector configurations.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import Dict, Set, List
from src.core.constants import PortRisk, PortCategory


# ============================================================================
# Port Definitions and Risk Classifications
# ============================================================================

# Database ports (highest risk)
DATABASE_PORTS: Set[int] = {
    3306,   # MySQL
    5432,   # PostgreSQL
    1433,   # MS SQL Server
    1521,   # Oracle
    27017,  # MongoDB
    6379,   # Redis
    9200,   # Elasticsearch
    5984,   # CouchDB
    7000,   # Cassandra
    8086,   # InfluxDB
}

# Admin/Management interface ports
ADMIN_PORTS: Set[int] = {
    8080,   # Common admin panels
    8443,   # HTTPS admin
    9090,   # Various admin interfaces
    10000,  # Webmin
    2082,   # cPanel
    2083,   # cPanel SSL
    8888,   # Common admin
}

# Remote access ports (high risk)
# Note: FTP (21) provides remote filesystem access
REMOTE_ACCESS_PORTS: Set[int] = {
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    3389,   # RDP
    5900,   # VNC
    5901,   # VNC
    5902,   # VNC (additional VNC display)
}

# Unencrypted protocol ports (should use TLS)
# NOTE: Port 80 (HTTP) is NOT included - web services are handled separately
# via httpx redirect detection, not tlsx unencrypted protocol detection
UNENCRYPTED_PROTOCOL_PORTS: Set[int] = {
    21,     # FTP (should use FTPS)
    23,     # Telnet (should use SSH)
    # 80 - HTTP handled by httpx redirect detection, not here
    110,    # POP3 (should use POP3S)
    143,    # IMAP (should use IMAPS)
    3306,   # MySQL (should use TLS)
    5432,   # PostgreSQL (should use TLS)
    6379,   # Redis (should use TLS)
    27017,  # MongoDB (should use TLS)
}

# Ports that are typically encrypted
ENCRYPTED_PORTS: Set[int] = {
    22,     # SSH
    443,    # HTTPS
    465,    # SMTPS
    587,    # SMTP with STARTTLS
    993,    # IMAPS
    995,    # POP3S
    8443,   # HTTPS alternate
}


# ============================================================================
# Comprehensive Port Information Database
# ============================================================================

PORT_INFO: Dict[int, Dict[str, str]] = {
    # File Transfer
    21: {
        "name": "FTP",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.FILE_TRANSFER.value,
        "description": "FTP (File Transfer Protocol) - Transmits credentials in cleartext",
        "remediation": "Use FTPS (port 990) or SFTP (port 22) instead"
    },
    22: {
        "name": "SSH",
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.REMOTE_ACCESS.value,
        "description": "SSH (Secure Shell) - Remote access protocol",
        "remediation": "Ensure key-based authentication, disable password auth, use fail2ban"
    },

    # Telnet
    23: {
        "name": "Telnet",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.REMOTE_ACCESS.value,
        "description": "Telnet - Unencrypted remote access, transmits passwords in cleartext",
        "remediation": "Disable telnet completely, use SSH instead"
    },

    # SMTP
    25: {
        "name": "SMTP",
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.EMAIL.value,
        "description": "SMTP (Simple Mail Transfer Protocol)",
        "remediation": "Configure SPF/DKIM/DMARC, require authentication"
    },

    # DNS
    53: {
        "name": "DNS",
        "risk": PortRisk.LOW.value,
        "category": PortCategory.OTHER.value,
        "description": "DNS (Domain Name System)",
        "remediation": "Restrict zone transfers, use DNSSEC"
    },

    # HTTP
    80: {
        "name": "HTTP",
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.WEB.value,
        "description": "HTTP - Unencrypted web traffic",
        "remediation": "Redirect all traffic to HTTPS (port 443)"
    },

    # POP3
    110: {
        "name": "POP3",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.EMAIL.value,
        "description": "POP3 - Unencrypted email retrieval",
        "remediation": "Use POP3S (port 995) instead"
    },

    # IMAP
    143: {
        "name": "IMAP",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.EMAIL.value,
        "description": "IMAP - Unencrypted email access",
        "remediation": "Use IMAPS (port 993) instead"
    },

    # HTTPS
    443: {
        "name": "HTTPS",
        "risk": PortRisk.LOW.value,
        "category": PortCategory.WEB.value,
        "description": "HTTPS - Encrypted web traffic",
        "remediation": "Ensure TLS 1.2+, use strong ciphers"
    },

    # SMTPS
    465: {
        "name": "SMTPS",
        "risk": PortRisk.LOW.value,
        "category": PortCategory.EMAIL.value,
        "description": "SMTPS - SMTP over SSL/TLS",
        "remediation": "Require authentication, monitor for abuse"
    },

    # MS SQL Server
    1433: {
        "name": "MS SQL Server",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "Microsoft SQL Server - Database exposure",
        "remediation": "Never expose to internet, use firewall, require strong auth"
    },

    # Oracle
    1521: {
        "name": "Oracle",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "Oracle Database - Database exposure",
        "remediation": "Never expose to internet, use firewall, enable encryption"
    },

    # MySQL
    3306: {
        "name": "MySQL",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "MySQL/MariaDB - Database exposure",
        "remediation": "Never expose to internet, bind to localhost, require SSL"
    },

    # RDP
    3389: {
        "name": "RDP",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.REMOTE_ACCESS.value,
        "description": "RDP (Remote Desktop Protocol) - Windows remote access",
        "remediation": "Use VPN, enable NLA, use strong passwords, limit access"
    },

    # PostgreSQL
    5432: {
        "name": "PostgreSQL",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "PostgreSQL - Database exposure",
        "remediation": "Never expose to internet, require SSL, use strong passwords"
    },

    # VNC
    5900: {
        "name": "VNC",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.REMOTE_ACCESS.value,
        "description": "VNC (Virtual Network Computing) - Remote desktop access",
        "remediation": "Use VPN or SSH tunnel, enable strong authentication"
    },

    # Redis
    6379: {
        "name": "Redis",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "Redis - In-memory database/cache exposure",
        "remediation": "Never expose to internet, require authentication, disable dangerous commands"
    },

    # HTTP Proxy
    8080: {
        "name": "HTTP Proxy",
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.ADMIN.value,
        "description": "HTTP Proxy/Admin - Alternative HTTP port",
        "remediation": "Use HTTPS, require authentication, restrict access"
    },

    # HTTPS Alt
    8443: {
        "name": "HTTPS Alt",
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.ADMIN.value,
        "description": "Alternative HTTPS port, often for admin panels",
        "remediation": "Use strong TLS, require authentication, restrict access"
    },

    # Elasticsearch
    9200: {
        "name": "Elasticsearch",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "Elasticsearch - Search engine and database",
        "remediation": "Never expose to internet, enable authentication, use firewall"
    },

    # MongoDB
    27017: {
        "name": "MongoDB",
        "risk": PortRisk.CRITICAL.value,
        "category": PortCategory.DATABASE.value,
        "description": "MongoDB - NoSQL database exposure",
        "remediation": "Never expose to internet, enable authentication, use TLS"
    },
}


# ============================================================================
# Risk Score Mappings for Keywords
# ============================================================================

# Keywords in finding titles/descriptions that affect base score
KEYWORD_RISK_SCORES: Dict[str, int] = {
    # Critical keywords (35-38 points)
    "database": 38,
    "credential": 38,
    "password": 38,
    "rce": 38,
    "injection": 38,
    "authentication": 36,

    # High keywords (28-32 points)
    "exposed": 30,
    "vulnerable": 30,
    "weak": 30,
    "unencrypted": 32,
    "cleartext": 32,

    # Medium keywords (20-25 points)
    "missing": 25,
    "misconfiguration": 25,
    "deprecated": 23,
    "outdated": 23,

    # Low keywords (8-12 points)
    "discovered": 10,
    "identified": 10,
    "detected": 10,
}


# ============================================================================
# Asset Criticality Multipliers
# ============================================================================

ASSET_CRITICALITY: Dict[str, float] = {
    "production": 1.0,
    "staging": 0.8,
    "development": 0.6,
    "test": 0.4,
}


# ============================================================================
# Port Risk Level Classification
# ============================================================================

def get_port_risk_level(port: int) -> str:
    """
    Get risk level for a port number.

    Args:
        port: Port number

    Returns:
        Risk level string (critical/high/medium/low/info)
    """
    if port in PORT_INFO:
        return PORT_INFO[port]["risk"]

    # Default to 'info' for unknown ports
    return PortRisk.INFO.value


def get_port_category(port: int) -> str:
    """
    Get category for a port number.

    Args:
        port: Port number

    Returns:
        Category string
    """
    if port in DATABASE_PORTS:
        return PortCategory.DATABASE.value
    elif port in ADMIN_PORTS:
        return PortCategory.ADMIN.value
    elif port in REMOTE_ACCESS_PORTS:
        return PortCategory.REMOTE_ACCESS.value
    elif port in PORT_INFO:
        return PORT_INFO[port].get("category", PortCategory.OTHER.value)
    else:
        return PortCategory.OTHER.value


def is_encrypted_port(port: int) -> bool:
    """
    Check if port typically uses encryption.

    Args:
        port: Port number

    Returns:
        True if port typically encrypted
    """
    return port in ENCRYPTED_PORTS


def requires_tls_check(port: int) -> bool:
    """
    Check if port should be verified for TLS encryption.

    Args:
        port: Port number

    Returns:
        True if port should use TLS
    """
    return port in UNENCRYPTED_PROTOCOL_PORTS
