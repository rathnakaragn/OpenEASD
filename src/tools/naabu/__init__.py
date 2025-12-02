"""
Naabu Tool - Fast Port Scanner

External tool for high-speed port discovery.
Install: https://github.com/projectdiscovery/naabu

Features:
- Fast SYN/CONNECT scanning
- Top ports discovery
- JSON output
- IPv4/IPv6 support
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

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_naabu(
    targets: List[str],
    top_ports: int = None,
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run naabu to scan ports.

    Args:
        targets: List of target hosts to scan
        top_ports: Number of top ports to scan (default: 1000)
        timeout: Timeout in seconds (default from config)

    Returns:
        List of port dictionaries with structure:
        {
            'subdomain': 'example.com',
            'port': 443,
            'protocol': 'tcp',
            'ip': '1.2.3.4'
        }

    Raises:
        Exception: If naabu times out or is not installed

    Example:
        >>> ports = run_naabu(['example.com'], top_ports=100)
        >>> ports[0]
        {'subdomain': 'example.com', 'port': 443, 'protocol': 'tcp', 'ip': '93.184.216.34'}
    """
    if not targets:
        return []

    targets = validate_domains(targets)

    if top_ports is None:
        top_ports = config.get('naabu.top_ports', 1000)
    if timeout is None:
        timeout = config.get('naabu.timeout', 300)

    targets_file = None
    try:
        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        naabu_path = config.get('tools.naabu.path', 'naabu')

        result = subprocess.run(
            [naabu_path, '-list', targets_file, '-top-ports', str(top_ports), '-json', '-silent'],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        ports = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data:
                    ports.append({
                        'subdomain': data.get('host', ''),
                        'port': data.get('port', 0),
                        'protocol': data.get('protocol', 'tcp'),
                        'ip': data.get('ip', '')
                    })

        logger.info(f"Naabu discovered {len(ports)} open ports")
        return ports

    except subprocess.TimeoutExpired:
        raise Exception(f"Naabu timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception(
            "Naabu not found. Please install: "
            "https://github.com/projectdiscovery/naabu"
        )
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)


__all__ = ['run_naabu']
