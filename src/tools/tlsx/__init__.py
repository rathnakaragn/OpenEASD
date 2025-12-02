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

import subprocess
import json
import tempfile
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple

from src.utils.config import Config
from src.utils.json_utils import safe_json_load

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def run_tlsx(
    targets: List[Tuple[str, int]],
    timeout: int = None
) -> List[Dict[str, Any]]:
    """
    Run tlsx to verify TLS/SSL status on ports.

    Uses ProjectDiscovery's tlsx to check if a service has TLS enabled.
    This is useful for detecting unencrypted protocols that should use TLS.

    Args:
        targets: List of (host, port) tuples to scan
        timeout: Timeout in seconds (default from config)

    Returns:
        List of TLS probe results:
        [
            {
                'host': 'example.com',
                'port': 443,
                'ip': '1.2.3.4',
                'tls_enabled': True,
                'tls_version': 'tls13',
                'cipher': 'TLS_AES_128_GCM_SHA256',
                'subject_cn': '*.example.com',
                'issuer_cn': 'DigiCert',
                'not_before': '2024-01-01T00:00:00Z',
                'not_after': '2025-01-01T00:00:00Z',
                'expired': False,
                'self_signed': False,
                'wildcard': True,
                'error': None
            },
            ...
        ]

    Raises:
        Exception: If tlsx is not found or times out

    Example:
        >>> results = run_tlsx([('example.com', 443)])
        >>> results[0]['tls_enabled']
        True
    """
    if not targets:
        return []

    if timeout is None:
        timeout = config.get('workflow.default_timeout', 120)

    targets_file = None
    try:
        # Find tlsx binary
        pdtm_path = os.path.expanduser('~/.pdtm/go/bin/tlsx')
        if os.path.exists(pdtm_path):
            tlsx_cmd = pdtm_path
        else:
            tlsx_cmd = config.get('tools.tlsx.path', 'tlsx')

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for host, port in targets:
                f.write(f"{host}:{port}\n")
            targets_file = f.name

        # Run tlsx with JSON output
        cmd = [
            tlsx_cmd,
            '-l', targets_file,
            '-json',
            '-silent',
            '-tps',       # Probe status
            '-tv',        # TLS version
            '-cipher',    # Cipher info
            '-ex',        # Expired check
            '-ss',        # Self-signed check
            '-wc',        # Wildcard cert check
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        probes = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data:
                    probes.append({
                        'host': data.get('host', ''),
                        'port': int(data.get('port', 0)),
                        'ip': data.get('ip', ''),
                        'tls_enabled': data.get('probe_status', False),
                        'tls_version': data.get('tls_version', ''),
                        'cipher': data.get('cipher', ''),
                        'subject_cn': data.get('subject_cn', ''),
                        'issuer_cn': data.get('issuer_cn', ''),
                        'issuer_org': data.get('issuer_org', []),
                        'not_before': data.get('not_before', ''),
                        'not_after': data.get('not_after', ''),
                        'expired': data.get('expired', False),
                        'self_signed': data.get('self_signed', False),
                        'wildcard': data.get('wildcard_certificate', False),
                        'error': data.get('error', None) if not data.get('probe_status', False) else None
                    })

        logger.info(f"tlsx scanned {len(probes)} targets")
        return probes

    except subprocess.TimeoutExpired:
        raise Exception(f"tlsx timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception(
            "tlsx not found. Please install: "
            "https://github.com/projectdiscovery/tlsx"
        )
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)


def run_tlsx_parallel(
    targets: List[Tuple[str, int]],
    batch_size: int = 50,
    timeout: int = None
) -> Dict[str, Dict[str, Any]]:
    """
    Run tlsx in batches for better performance on many targets.

    Args:
        targets: List of (host, port) tuples
        batch_size: Number of targets per batch (default: 50)
        timeout: Timeout per batch

    Returns:
        Dictionary mapping "host:port" to TLS probe result

    Example:
        >>> results = run_tlsx_parallel([('example.com', 443)])
        >>> results['example.com:443']['tls_enabled']
        True
    """
    results = {}

    if not targets:
        return results

    try:
        # tlsx handles parallelism internally, so we just run it once
        probes = run_tlsx(targets, timeout=timeout)

        for probe in probes:
            key = f"{probe['host']}:{probe['port']}"
            results[key] = probe

    except Exception as e:
        logger.error(f"tlsx scan failed: {e}")
        # Mark all targets as unknown
        for host, port in targets:
            key = f"{host}:{port}"
            results[key] = {
                'host': host,
                'port': port,
                'tls_enabled': None,  # Unknown
                'error': str(e)
            }

    return results


__all__ = ['run_tlsx', 'run_tlsx_parallel']
