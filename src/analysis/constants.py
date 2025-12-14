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
# Note: 8443 removed - it's standard HTTPS alt, not necessarily admin
ADMIN_PORTS: Set[int] = {
    9090,   # Various admin interfaces (Cockpit, Prometheus)
    10000,  # Webmin
    2082,   # cPanel
    2083,   # cPanel SSL
    2086,   # WHM
    2087,   # WHM SSL
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
    636,    # LDAPS
    993,    # IMAPS
    995,    # POP3S
    8443,   # HTTPS alternate
}

# Email service ports (check for open relay, missing auth)
EMAIL_PORTS: Set[int] = {
    25,     # SMTP
    465,    # SMTPS
    587,    # SMTP Submission
}

# Directory service ports (check for anonymous bind)
DIRECTORY_PORTS: Set[int] = {
    389,    # LDAP (unencrypted)
    636,    # LDAPS (encrypted)
}

# Infrastructure ports (DNS, SNMP - special checks needed)
INFRASTRUCTURE_PORTS: Set[int] = {
    53,     # DNS
    161,    # SNMP
    162,    # SNMP Trap
}

# Ports requiring special security checks
SPECIAL_CHECK_PORTS: Set[int] = {
    25,     # SMTP - open relay check
    53,     # DNS - zone transfer check
    161,    # SNMP - community string check
    389,    # LDAP - anonymous bind check
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
        "risk": PortRisk.MEDIUM.value,
        "category": PortCategory.OTHER.value,
        "description": "DNS (Domain Name System) - Potential zone transfer exposure",
        "remediation": "Restrict zone transfers (AXFR), use DNSSEC, limit recursion"
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

    # SNMP
    161: {
        "name": "SNMP",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.OTHER.value,
        "description": "SNMP (Simple Network Management Protocol) - Often uses default community strings",
        "remediation": "Use SNMPv3 with authentication, change default community strings, restrict access"
    },

    # LDAP
    389: {
        "name": "LDAP",
        "risk": PortRisk.HIGH.value,
        "category": PortCategory.OTHER.value,
        "description": "LDAP (Lightweight Directory Access Protocol) - Unencrypted, may allow anonymous bind",
        "remediation": "Use LDAPS (port 636), disable anonymous bind, require authentication"
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

    # HTTP Alt (standard web port - not risky)
    8080: {
        "name": "HTTP Alt",
        "risk": PortRisk.LOW.value,
        "category": PortCategory.WEB.value,
        "description": "Alternative HTTP port - standard web service",
        "remediation": "Redirect to HTTPS if serving web content"
    },

    # HTTPS Alt (standard web port - not risky)
    8443: {
        "name": "HTTPS Alt",
        "risk": PortRisk.LOW.value,
        "category": PortCategory.WEB.value,
        "description": "Alternative HTTPS port - standard web service",
        "remediation": "Ensure TLS 1.2+, use strong ciphers"
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
# Version-Based Vulnerability Detection
# ============================================================================

# Known vulnerable service versions (service_name -> list of version patterns)
# Format: {"service": [{"pattern": "regex", "severity": "critical/high/medium", "cve": "CVE-xxx", "description": "..."}]}
VULNERABLE_VERSIONS: Dict[str, List[Dict[str, str]]] = {
    "openssh": [
        {"pattern": r"^[1-6]\.", "severity": "critical", "cve": "Multiple CVEs", "description": "OpenSSH < 7.0 has multiple critical vulnerabilities"},
        {"pattern": r"^7\.[0-3]", "severity": "high", "cve": "CVE-2016-10009", "description": "OpenSSH 7.0-7.3 vulnerable to agent forwarding attack"},
    ],
    "apache": [
        {"pattern": r"^2\.2\.", "severity": "high", "cve": "Multiple CVEs", "description": "Apache 2.2.x is end-of-life with known vulnerabilities"},
        {"pattern": r"^2\.4\.([0-9]|[1-3][0-9]|4[0-9])$", "severity": "medium", "cve": "CVE-2021-44790", "description": "Apache < 2.4.52 vulnerable to buffer overflow"},
    ],
    "nginx": [
        {"pattern": r"^1\.(1[0-7]|[0-9])\.", "severity": "high", "cve": "Multiple CVEs", "description": "Nginx < 1.18 has known vulnerabilities"},
    ],
    "mysql": [
        {"pattern": r"^5\.[0-5]\.", "severity": "critical", "cve": "Multiple CVEs", "description": "MySQL 5.0-5.5 is end-of-life"},
        {"pattern": r"^5\.6\.", "severity": "high", "cve": "Multiple CVEs", "description": "MySQL 5.6 is end-of-life"},
        {"pattern": r"^5\.7\.", "severity": "medium", "cve": "Multiple CVEs", "description": "MySQL 5.7 approaching end-of-life"},
    ],
    "postgresql": [
        {"pattern": r"^[0-9]\.", "severity": "critical", "cve": "Multiple CVEs", "description": "PostgreSQL < 10 is end-of-life"},
        {"pattern": r"^1[0-1]\.", "severity": "high", "cve": "Multiple CVEs", "description": "PostgreSQL 10-11 approaching end-of-life"},
    ],
    "redis": [
        {"pattern": r"^[0-4]\.", "severity": "critical", "cve": "Multiple CVEs", "description": "Redis < 5.0 has critical vulnerabilities"},
        {"pattern": r"^5\.", "severity": "medium", "cve": "CVE-2021-32761", "description": "Redis 5.x has known vulnerabilities"},
    ],
    "mongodb": [
        {"pattern": r"^[0-3]\.", "severity": "critical", "cve": "Multiple CVEs", "description": "MongoDB < 4.0 has critical vulnerabilities"},
    ],
    "proftpd": [
        {"pattern": r"^1\.[0-2]\.", "severity": "critical", "cve": "CVE-2015-3306", "description": "ProFTPD < 1.3.5 vulnerable to RCE"},
    ],
    "vsftpd": [
        {"pattern": r"^[0-2]\.", "severity": "high", "cve": "Multiple CVEs", "description": "vsftpd < 3.0 has known vulnerabilities"},
    ],
    "openssl": [
        {"pattern": r"^0\.", "severity": "critical", "cve": "Multiple CVEs", "description": "OpenSSL 0.x is severely outdated"},
        {"pattern": r"^1\.0\.", "severity": "critical", "cve": "CVE-2014-0160", "description": "OpenSSL 1.0.x may be vulnerable to Heartbleed"},
        {"pattern": r"^1\.1\.0", "severity": "high", "cve": "Multiple CVEs", "description": "OpenSSL 1.1.0 is end-of-life"},
    ],
}

# TLS versions and their risk levels
TLS_VERSION_RISK: Dict[str, Dict[str, str]] = {
    "ssl2": {"severity": "critical", "description": "SSLv2 is obsolete and critically insecure"},
    "ssl3": {"severity": "critical", "description": "SSLv3 is vulnerable to POODLE attack"},
    "tls10": {"severity": "high", "description": "TLS 1.0 is deprecated and insecure"},
    "tls11": {"severity": "high", "description": "TLS 1.1 is deprecated and should not be used"},
    "tls12": {"severity": "info", "description": "TLS 1.2 is acceptable but TLS 1.3 preferred"},
    "tls13": {"severity": "info", "description": "TLS 1.3 is the recommended version"},
}

# Weak cipher patterns
WEAK_CIPHER_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r"RC4", "severity": "high", "description": "RC4 cipher is broken"},
    {"pattern": r"DES", "severity": "high", "description": "DES/3DES ciphers are weak"},
    {"pattern": r"NULL", "severity": "critical", "description": "NULL cipher provides no encryption"},
    {"pattern": r"EXPORT", "severity": "critical", "description": "EXPORT ciphers are critically weak"},
    {"pattern": r"MD5", "severity": "medium", "description": "MD5 in cipher suite is deprecated"},
    {"pattern": r"anon", "severity": "critical", "description": "Anonymous cipher allows MITM attacks"},
]


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
