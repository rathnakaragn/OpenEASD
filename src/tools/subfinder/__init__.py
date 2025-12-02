"""
Subfinder Tool - Passive Subdomain Discovery

External tool called via subprocess from CLI commands.
Install: https://github.com/projectdiscovery/subfinder

Usage in CLI:
    openeasd scan domain example.com
    openeasd scan subfinder --primary
"""

import subprocess
import json
import logging
from typing import List

from src.utils.config import Config
from src.utils.validation import validate_domain
from src.utils.json_utils import safe_json_load

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_subfinder(domain: str, timeout: int = None) -> List[str]:
    """
    Run subfinder to discover subdomains.

    Args:
        domain: Target domain to enumerate
        timeout: Timeout in seconds (default from config)

    Returns:
        List of discovered subdomains

    Raises:
        Exception: If subfinder times out or is not installed

    Example:
        >>> subdomains = run_subfinder('example.com', timeout=300)
        >>> print(subdomains)
        ['www.example.com', 'mail.example.com', 'api.example.com']
    """
    domain = validate_domain(domain)

    if timeout is None:
        timeout = config.get('subfinder.timeout', 300)

    try:
        subfinder_path = config.get('tools.subfinder.path', 'subfinder')

        result = subprocess.run(
            [subfinder_path, '-d', domain, '-silent', '-json'],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        subdomains = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data and 'host' in data:
                    subdomains.append(data['host'])

        logger.info(f"Subfinder discovered {len(subdomains)} subdomains for {domain}")
        return subdomains

    except subprocess.TimeoutExpired:
        raise Exception(f"Subfinder timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception(
            "Subfinder not found. Please install: "
            "https://github.com/projectdiscovery/subfinder"
        )


__all__ = ['run_subfinder']
