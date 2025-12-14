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

import subprocess
import json
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from src.utils.config import Config
from src.utils.validation import validate_domains
from src.utils.json_utils import safe_json_load
from src.tools.exceptions import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
)

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_dnsx(
    domains: List[str],
    record_types: List[str] = None,
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run dnsx to perform DNS queries.

    Args:
        domains: List of domains to resolve
        record_types: List of record types to query (a, aaaa, cname, mx, ns, txt, ptr, soa, srv)
        timeout: Timeout in seconds (default from config)

    Returns:
        List of DNS record dictionaries with structure:
        {
            'host': 'example.com',
            'a': ['1.2.3.4'],
            'aaaa': [],
            'cname': [],
            'mx': ['mail.example.com'],
            'ns': ['ns1.example.com'],
            'txt': [],
            'ptr': [],
            'soa': [],
            'srv': []
        }

    Raises:
        ToolTimeoutError: If dnsx times out
        ToolNotFoundError: If dnsx is not installed
        ToolExecutionError: If dnsx returns non-zero exit code

    Example:
        >>> records = run_dnsx(['example.com'], record_types=['a', 'mx'])
        >>> records[0]['a']
        ['93.184.216.34']
    """
    if not domains:
        return []

    domains = validate_domains(domains)

    if timeout is None:
        timeout = config.get('workflow.default_timeout', 300)

    domains_file = None
    try:
        # Write domains to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for domain in domains:
                f.write(f"{domain}\n")
            domains_file = f.name

        # Build dnsx command
        dnsx_path = config.get('tools.dnsx.path', 'dnsx')
        cmd = [dnsx_path, '-l', domains_file, '-json', '-silent', '-resp']

        # Add record types
        if record_types:
            for rtype in record_types:
                rtype_lower = rtype.lower()
                if rtype_lower in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'ptr', 'soa', 'srv']:
                    cmd.append(f'-{rtype_lower}')
        else:
            cmd.append('-a')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # Validate return code
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
            logger.error(f"dnsx failed with exit code {result.returncode}: {error_msg}")
            raise ToolExecutionError(f"dnsx failed: {error_msg}")

        def normalize_records(record_list):
            if not record_list:
                return []
            return [str(item) if not isinstance(item, dict) else str(item)
                    for item in record_list]

        records = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data:
                    records.append({
                        'host': data.get('host', ''),
                        'a': normalize_records(data.get('a', [])),
                        'aaaa': normalize_records(data.get('aaaa', [])),
                        'cname': normalize_records(data.get('cname', [])),
                        'mx': normalize_records(data.get('mx', [])),
                        'ns': normalize_records(data.get('ns', [])),
                        'txt': normalize_records(data.get('txt', [])),
                        'ptr': normalize_records(data.get('ptr', [])),
                        'soa': normalize_records(data.get('soa', [])),
                        'srv': normalize_records(data.get('srv', []))
                    })

        logger.info(f"dnsx resolved {len(records)} domains")
        return records

    except subprocess.TimeoutExpired:
        raise ToolTimeoutError(f"dnsx timed out after {timeout} seconds")
    except FileNotFoundError:
        raise ToolNotFoundError(
            "dnsx not found. Install: https://github.com/projectdiscovery/dnsx"
        )
    finally:
        if domains_file and Path(domains_file).exists():
            Path(domains_file).unlink(missing_ok=True)


__all__ = ['run_dnsx']
