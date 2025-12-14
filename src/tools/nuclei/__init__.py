"""
Nuclei Tool - Fast Vulnerability Scanner

External tool for vulnerability detection on both web and non-web services.
Install: https://github.com/projectdiscovery/nuclei

Features:
- Template-based scanning
- Network protocol support (non-web)
- HTTP/HTTPS vulnerability detection
- CVE detection
- Misconfiguration detection
- JSON output for easy parsing

Usage:
    # Non-web services
    run_nuclei_network(['host:3306', 'host:6379'])

    # Web services
    run_nuclei_web(['https://example.com'])
"""

import subprocess
import tempfile
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils.config import Config
from src.utils.json_utils import safe_json_load
from src.tools.exceptions import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
)

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def _get_nuclei_cmd() -> str:
    """Get nuclei binary path."""
    pdtm_path = os.path.expanduser('~/.pdtm/go/bin/nuclei')
    if os.path.exists(pdtm_path):
        return pdtm_path
    return config.get('tools.nuclei.path', 'nuclei')


def run_nuclei_network(
    targets: List[str],
    templates: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150
) -> List[Dict[str, Any]]:
    """
    Run nuclei with network templates for non-web services.

    Args:
        targets: List of host:port strings (e.g., ['192.168.1.1:3306', '192.168.1.1:6379'])
        templates: Template paths to use (default: network templates)
        severity: Filter by severity (e.g., ['critical', 'high'])
        timeout: Timeout in seconds
        rate_limit: Requests per second limit

    Returns:
        List of vulnerability findings:
        [
            {
                'template_id': 'mysql-native-password-bruteforce',
                'template_name': 'MySQL Native Password Bruteforce',
                'severity': 'high',
                'host': '192.168.1.1:3306',
                'matched_at': '192.168.1.1:3306',
                'type': 'network',
                'description': '...',
                'tags': ['mysql', 'network', 'bruteforce'],
                'reference': ['https://...'],
                'cvss_score': 7.5,
                'cve_id': 'CVE-XXXX-XXXX'  # if applicable
            }
        ]

    Raises:
        ToolTimeoutError: If nuclei times out
        ToolNotFoundError: If nuclei is not installed
        ToolExecutionError: If nuclei fails

    Example:
        >>> results = run_nuclei_network(['db.example.com:3306'])
        >>> results[0]['severity']
        'high'
    """
    if not targets:
        return []

    if templates is None:
        templates = [
            'network/cves/',
            'network/exposures/',
            'network/misconfiguration/',
            'network/default-logins/',
        ]

    targets_file = None
    try:
        nuclei_cmd = _get_nuclei_cmd()

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        # Build command
        cmd = [
            nuclei_cmd,
            '-l', targets_file,
            '-json',
            '-silent',
            '-rate-limit', str(rate_limit),
            '-timeout', str(min(timeout // len(targets) if targets else 30, 30)),
        ]

        # Add templates
        for template in templates:
            cmd.extend(['-t', template])

        # Add severity filter if specified
        if severity:
            cmd.extend(['-severity', ','.join(severity)])

        logger.debug(f"Running nuclei network scan on {len(targets)} targets")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output (one JSON object per line)
        findings = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = safe_json_load(line, default={})
                if data:
                    finding = _parse_nuclei_result(data)
                    if finding:
                        findings.append(finding)

        logger.info(f"Nuclei network scan found {len(findings)} vulnerabilities")
        return findings

    except subprocess.TimeoutExpired:
        raise ToolTimeoutError(f"Nuclei timed out after {timeout} seconds")
    except FileNotFoundError:
        raise ToolNotFoundError(
            "Nuclei not found. Install: https://github.com/projectdiscovery/nuclei"
        )
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)


def run_nuclei_network_parallel(
    targets: List[str],
    templates: Optional[List[str]] = None,
    max_workers: int = 3,
    timeout: int = 60
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run nuclei network scan in parallel batches.

    Args:
        targets: List of host:port strings
        templates: Template paths to use
        max_workers: Number of parallel batches
        timeout: Timeout per batch

    Returns:
        Dictionary mapping target to list of findings

    Example:
        >>> results = run_nuclei_network_parallel(['db1:3306', 'db2:3306'])
        >>> results['db1:3306']
        [{'severity': 'high', ...}]
    """
    if not targets:
        return {}

    results = {}
    batch_size = max(1, len(targets) // max_workers)
    batches = [targets[i:i + batch_size] for i in range(0, len(targets), batch_size)]

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for batch in batches:
                future = executor.submit(
                    run_nuclei_network,
                    targets=batch,
                    templates=templates,
                    timeout=timeout
                )
                futures[future] = batch

            for future in as_completed(futures.keys()):
                batch = futures[future]
                try:
                    findings = future.result(timeout=timeout + 10)
                    # Map findings to targets
                    for finding in findings:
                        target = finding.get('host', '')
                        if target not in results:
                            results[target] = []
                        results[target].append(finding)
                except Exception as e:
                    logger.warning(f"Nuclei batch failed: {e}")
                    for target in batch:
                        if target not in results:
                            results[target] = []

    except Exception as e:
        logger.error(f"Nuclei parallel execution failed: {e}")

    return results


def run_nuclei_service(
    host: str,
    port: int,
    service: str,
    timeout: int = 60
) -> List[Dict[str, Any]]:
    """
    Run nuclei for a specific service type.

    Args:
        host: Target hostname
        port: Target port
        service: Service name (mysql, redis, mongodb, ssh, etc.)
        timeout: Timeout in seconds

    Returns:
        List of vulnerability findings
    """
    # Map service to specific templates
    service_templates = {
        'mysql': ['network/cves/mysql/', 'network/exposures/mysql/', 'network/default-logins/mysql/'],
        'redis': ['network/cves/redis/', 'network/exposures/redis/'],
        'mongodb': ['network/cves/mongodb/', 'network/exposures/mongodb/'],
        'postgresql': ['network/cves/postgresql/', 'network/exposures/postgresql/'],
        'ssh': ['network/cves/ssh/', 'network/misconfiguration/ssh/'],
        'ftp': ['network/cves/ftp/', 'network/default-logins/ftp/', 'network/exposures/ftp/'],
        'smtp': ['network/cves/smtp/', 'network/exposures/smtp/'],
        'telnet': ['network/cves/telnet/', 'network/exposures/telnet/'],
        'vnc': ['network/cves/vnc/', 'network/exposures/vnc/'],
        'rdp': ['network/cves/rdp/', 'network/exposures/rdp/'],
        'memcached': ['network/cves/memcached/', 'network/exposures/memcached/'],
        'elasticsearch': ['network/cves/elasticsearch/', 'network/exposures/elasticsearch/'],
        'ldap': ['network/cves/ldap/', 'network/exposures/ldap/'],
    }

    templates = service_templates.get(service.lower(), ['network/'])
    target = f"{host}:{port}"

    return run_nuclei_network([target], templates=templates, timeout=timeout)


def _parse_nuclei_result(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse nuclei JSON output into standardized finding format.

    Args:
        data: Raw nuclei JSON output

    Returns:
        Standardized finding dictionary or None
    """
    if not data:
        return None

    info = data.get('info', {})

    # Extract CVE ID if present
    cve_id = None
    classification = info.get('classification', {})
    if classification:
        cve_ids = classification.get('cve-id', [])
        if cve_ids:
            cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids

    # Extract CVSS score
    cvss_score = None
    if classification:
        cvss_metrics = classification.get('cvss-metrics', '')
        cvss_score = classification.get('cvss-score', 0)
        if not cvss_score and cvss_metrics:
            # Try to extract from metrics string
            try:
                cvss_score = float(cvss_metrics.split('/')[-1]) if '/' in cvss_metrics else None
            except (ValueError, IndexError):
                pass

    return {
        'template_id': data.get('template-id', ''),
        'template_name': info.get('name', ''),
        'severity': info.get('severity', 'unknown'),
        'host': data.get('host', ''),
        'matched_at': data.get('matched-at', ''),
        'type': data.get('type', 'network'),
        'description': info.get('description', ''),
        'tags': info.get('tags', []),
        'reference': info.get('reference', []),
        'cvss_score': cvss_score,
        'cve_id': cve_id,
        'matcher_name': data.get('matcher-name', ''),
        'extracted_results': data.get('extracted-results', []),
    }


__all__ = [
    'run_nuclei_network',
    'run_nuclei_network_parallel',
    'run_nuclei_service',
    'ToolExecutionError',
    'ToolTimeoutError',
    'ToolNotFoundError',
]
