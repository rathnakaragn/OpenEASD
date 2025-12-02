"""
Amass Tool - Comprehensive Subdomain Enumeration

External tool for advanced subdomain discovery.
Install: https://github.com/owasp-amass/amass

Features:
- Active and passive enumeration
- DNS resolution
- ASN mapping
- WHOIS lookups
- Multiple data sources

Usage in CLI:
    openeasd run amass example.com
    openeasd run amass example.com --passive
    openeasd run amass example.com --timeout 600
"""

import subprocess
import json
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.utils.config import Config
from src.utils.validation import validate_domain
from src.utils.json_utils import safe_json_load

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_amass(
    domain: str,
    passive: bool = True,
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run amass to discover subdomains.

    Amass performs comprehensive subdomain enumeration using multiple
    data sources including certificate transparency logs, DNS records,
    web archives, and more.

    Args:
        domain: Target domain to enumerate
        passive: If True, only use passive techniques (default: True)
                 If False, includes active DNS brute-forcing
        timeout: Timeout in seconds (default from config)

    Returns:
        List of subdomain dictionaries with structure:
        {
            'name': 'api.example.com',
            'domain': 'example.com',
            'addresses': [{'ip': '1.2.3.4', 'cidr': '1.2.3.0/24', 'asn': 12345}],
            'tag': 'cert',
            'sources': ['CertSpotter', 'Censys']
        }

    Raises:
        Exception: If amass times out or is not installed

    Example:
        >>> results = run_amass('example.com', passive=True)
        >>> results[0]['name']
        'api.example.com'
    """
    domain = validate_domain(domain)

    if timeout is None:
        timeout = config.get('amass.timeout', 600)  # Amass can take longer

    output_file = None
    try:
        # Get amass path from config
        amass_path = config.get('tools.amass.path', 'amass')

        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name

        # Build amass command
        cmd = [
            amass_path,
            'enum',
            '-d', domain,
            '-json', output_file,
            '-silent',
        ]

        # Add passive flag if requested (default)
        if passive:
            cmd.append('-passive')

        logger.debug(f"Running amass enum on {domain} (passive={passive})")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output file
        subdomains = []
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = safe_json_load(line, default={})
                        if data:
                            subdomains.append({
                                'name': data.get('name', ''),
                                'domain': data.get('domain', domain),
                                'addresses': data.get('addresses', []),
                                'tag': data.get('tag', ''),
                                'sources': data.get('sources', [])
                            })

        logger.info(f"Amass discovered {len(subdomains)} subdomains for {domain}")
        return subdomains

    except subprocess.TimeoutExpired:
        raise Exception(f"Amass timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception(
            "Amass not found. Please install: "
            "https://github.com/owasp-amass/amass"
        )
    finally:
        if output_file and Path(output_file).exists():
            Path(output_file).unlink(missing_ok=True)


def run_amass_intel(
    domain: str,
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run amass intel to discover related domains and infrastructure.

    Uses amass intel subcommand to find ASN information, WHOIS data,
    and related domains that may belong to the same organization.

    Args:
        domain: Target domain for intel gathering
        timeout: Timeout in seconds (default from config)

    Returns:
        List of intel results with structure:
        {
            'domain': 'related-domain.com',
            'asn': 12345,
            'cidr': '1.2.3.0/24',
            'org': 'Example Inc'
        }

    Raises:
        Exception: If amass times out or is not installed

    Example:
        >>> results = run_amass_intel('example.com')
        >>> results[0]['asn']
        12345
    """
    domain = validate_domain(domain)

    if timeout is None:
        timeout = config.get('amass.timeout', 300)

    output_file = None
    try:
        amass_path = config.get('tools.amass.path', 'amass')

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name

        cmd = [
            amass_path,
            'intel',
            '-d', domain,
            '-json', output_file,
            '-silent',
            '-whois',
        ]

        logger.debug(f"Running amass intel on {domain}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output
        intel_results = []
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = safe_json_load(line, default={})
                        if data:
                            intel_results.append({
                                'domain': data.get('domain', ''),
                                'asn': data.get('asn', 0),
                                'cidr': data.get('cidr', ''),
                                'org': data.get('desc', '')
                            })

        logger.info(f"Amass intel found {len(intel_results)} results for {domain}")
        return intel_results

    except subprocess.TimeoutExpired:
        raise Exception(f"Amass intel timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception(
            "Amass not found. Please install: "
            "https://github.com/owasp-amass/amass"
        )
    finally:
        if output_file and Path(output_file).exists():
            Path(output_file).unlink(missing_ok=True)


__all__ = ['run_amass', 'run_amass_intel']
