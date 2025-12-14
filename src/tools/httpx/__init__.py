"""
httpx Tool - Fast HTTP Toolkit

External tool for HTTP/HTTPS probing and enumeration.
Install: https://github.com/projectdiscovery/httpx

Features:
- Fast HTTP/HTTPS probing
- Status code detection
- Title extraction
- Content-length checking
- Technology detection
- Web server identification
- Multi-threaded scanning

Usage in CLI:
    openeasd run httpx example.com
    openeasd run httpx https://api.example.com
    openeasd run httpx example.com --threads 100
"""

import subprocess
import json
import tempfile
import os
import logging
from pathlib import Path
from typing import List, Dict, Any

from src.utils.config import Config
from src.utils.validation import validate_domain
from src.utils.json_utils import safe_json_load
from src.tools.exceptions import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
)

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_httpx(
    targets: List[str],
    threads: int = None,
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run httpx to probe HTTP/HTTPS services.

    Args:
        targets: List of URLs or host:port combinations to probe
        threads: Number of concurrent threads (default: 50)
        timeout: Timeout in seconds (default from config)

    Returns:
        List of HTTP probe results with structure:
        {
            'url': 'https://example.com',
            'host': 'example.com',
            'status_code': 200,
            'content_length': 1256,
            'title': 'Example Domain',
            'server': 'nginx',
            'technologies': ['nginx', 'cloudflare'],
            'webserver': 'nginx/1.21.0',
            'scheme': 'https',
            'port': 443
        }

    Raises:
        ToolTimeoutError: If httpx times out
        ToolNotFoundError: If httpx is not installed
        ToolExecutionError: If httpx returns non-zero exit code

    Example:
        >>> results = run_httpx(['https://example.com'])
        >>> results[0]['status_code']
        200
    """
    if not targets:
        return []

    # Validate domains from targets
    validated_targets = []
    for target in targets:
        domain = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        validate_domain(domain)
        validated_targets.append(target)
    targets = validated_targets

    if threads is None:
        threads = config.get('httpx.threads', 50)
    if timeout is None:
        timeout = config.get('workflow.default_timeout', 300)

    targets_file = None
    try:
        # Find httpx binary
        pdtm_path = os.path.expanduser('~/.pdtm/go/bin/httpx')
        if os.path.exists(pdtm_path):
            httpx_cmd = pdtm_path
        else:
            httpx_cmd = config.get('tools.httpx.path', 'httpx')

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        result = subprocess.run(
            [
                httpx_cmd, '-l', targets_file, '-json', '-silent',
                '-status-code', '-content-length', '-title',
                '-tech-detect', '-server', '-threads', str(threads)
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Validate return code
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
            logger.error(f"httpx failed with exit code {result.returncode}: {error_msg}")
            raise ToolExecutionError(f"httpx failed: {error_msg}")

        probes = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data:
                    probes.append({
                        'url': data.get('url', ''),
                        'host': data.get('host', ''),
                        'status_code': data.get('status_code', 0),
                        'content_length': data.get('content_length', 0),
                        'title': data.get('title', ''),
                        'server': data.get('server', ''),
                        'technologies': data.get('tech', []),
                        'webserver': data.get('webserver', ''),
                        'scheme': data.get('scheme', ''),
                        'port': data.get('port', '')
                    })

        logger.info(f"httpx probed {len(probes)} targets")
        return probes

    except subprocess.TimeoutExpired:
        raise ToolTimeoutError(f"httpx timed out after {timeout} seconds")
    except FileNotFoundError:
        raise ToolNotFoundError(
            "httpx not found. Install: https://github.com/projectdiscovery/httpx"
        )
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)


__all__ = ['run_httpx']
