"""
Nmap Tool - Network Mapper & Port Scanner

External tool for service detection and port scanning.
Install: https://nmap.org/

Features:
- Port scanning
- Service version detection (-sV)
- OS fingerprinting
- NSE scripting for vulnerability detection
- XML output parsing
"""

import subprocess
import re
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils.config import Config
from src.utils.validation import validate_domain

__version__ = "1.0.0"

logger = logging.getLogger(__name__)
config = Config()


def _parse_nmap_xml(xml_output: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Parse nmap XML output to extract service information.

    Args:
        xml_output: Raw XML output from nmap
        port: Port number to search for

    Returns:
        Dictionary with service info or None if not found
    """
    try:
        root = ET.fromstring(xml_output)

        # Find port element matching the port number
        for port_elem in root.findall(f".//port[@portid='{port}']"):
            state = port_elem.find('state')
            if state is not None and state.get('state') == 'open':
                service = port_elem.find('service')
                if service is not None:
                    return {
                        'name': service.get('name', 'unknown'),
                        'version': service.get('version', ''),
                        'confidence': int(service.get('conf', '0')),
                        'product': service.get('product', ''),
                        'extrainfo': service.get('extrainfo', ''),
                        'os_family': service.get('ostype', '')
                    }

        return None

    except ET.ParseError as e:
        logger.error(f"XML parsing failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing nmap output: {e}")
        return None


def _extract_cves_from_nmap_output(nmap_output: str) -> List[Dict[str, Any]]:
    """
    Extract CVE information from nmap NSE vulnerability output.

    Args:
        nmap_output: Raw nmap script output text

    Returns:
        List of CVE dictionaries sorted by CVSS score (highest first)
    """
    from src.utils.cve_severity import CVESeverityService

    cves = []

    try:
        # Extract CVE IDs from output
        cve_pattern = r'CVE-\d{4}-\d{4,5}'
        matches = re.findall(cve_pattern, nmap_output)

        # Deduplicate and process each unique CVE
        for cve_id in set(matches):
            severity_info = CVESeverityService.get_severity(cve_id)
            cves.append({
                'cve_id': cve_id,
                'severity': severity_info['severity'],
                'cvss': severity_info.get('cvss', 5.0),
                'description': severity_info.get('description', 'Known vulnerability'),
                'affected_versions': severity_info.get('affected_versions', [])
            })

        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x['cvss'], reverse=True)

    except Exception as e:
        logger.error(f"Error extracting CVEs from nmap output: {e}")

    return cves


def run_nmap_service_detection(
    host: str,
    port: int,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Use nmap -sV to identify service type and version.

    Args:
        host: Target hostname/IP
        port: Port number to scan
        timeout: Timeout in seconds

    Returns:
        Dictionary containing:
        {
            'service': 'mysql',
            'version': '5.7.30-0-log',
            'confidence': 95,
            'product': 'MySQL',
            'extrainfo': '0-log',
            'os_family': '',
            'status': 'success' | 'timeout' | 'no_match' | 'error'
        }

    Example:
        >>> result = run_nmap_service_detection('example.com', 3306)
        >>> result['service']
        'mysql'
    """
    try:
        validate_domain(host)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")

        nmap_cmd = config.get('tools.nmap.path', 'nmap')

        cmd = [
            nmap_cmd,
            '-sV',
            '--version-all',
            '-p', str(port),
            '--script-timeout', str(timeout),
            '-oX', '-',
            host
        ]

        logger.debug(f"Running nmap service detection on {host}:{port}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        service_info = _parse_nmap_xml(result.stdout, port)

        if service_info:
            return {
                'service': service_info.get('name', 'unknown'),
                'version': service_info.get('version', ''),
                'confidence': service_info.get('confidence', 0),
                'product': service_info.get('product', ''),
                'extrainfo': service_info.get('extrainfo', ''),
                'os_family': service_info.get('os_family', ''),
                'status': 'success'
            }
        else:
            return {
                'service': 'unknown',
                'version': '',
                'confidence': 0,
                'product': '',
                'extrainfo': '',
                'os_family': '',
                'status': 'no_match'
            }

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap timed out for {host}:{port} after {timeout} seconds")
        return {
            'service': 'unknown',
            'version': '',
            'confidence': 0,
            'product': '',
            'extrainfo': '',
            'os_family': '',
            'status': 'timeout'
        }
    except FileNotFoundError:
        raise Exception(
            "Nmap not found. Please install nmap: "
            "https://nmap.org/download.html"
        )
    except Exception as e:
        logger.error(f"Nmap service detection failed for {host}:{port}: {e}")
        return {
            'service': 'unknown',
            'version': '',
            'confidence': 0,
            'product': '',
            'extrainfo': '',
            'os_family': '',
            'status': 'error'
        }


def run_nmap_service_detection_parallel(
    ports_to_scan: List[Tuple[str, int]],
    max_workers: int = 5
) -> Dict[str, Dict[str, Any]]:
    """
    Run nmap service detection in parallel for multiple ports.

    Args:
        ports_to_scan: List of (host, port) tuples to scan
        max_workers: Number of concurrent nmap processes (default: 5)

    Returns:
        Dictionary mapping "host:port" keys to service detection results

    Example:
        >>> ports = [('example.com', 3306), ('example.com', 5432)]
        >>> results = run_nmap_service_detection_parallel(ports)
        >>> results['example.com:3306']['service']
        'mysql'
    """
    results = {}

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for host, port in ports_to_scan:
                port_key = f"{host}:{port}"
                future = executor.submit(
                    run_nmap_service_detection,
                    host=host,
                    port=port,
                    timeout=10
                )
                futures[future] = port_key

            for future in as_completed(futures.keys()):
                port_key = futures[future]
                try:
                    result = future.result(timeout=15)
                    results[port_key] = result
                    logger.debug(f"Nmap service detection completed for {port_key}: {result.get('service', 'unknown')}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Nmap service detection timed out for {port_key}")
                    results[port_key] = {
                        'service': 'unknown',
                        'version': '',
                        'confidence': 0,
                        'status': 'timeout'
                    }
                except Exception as e:
                    logger.error(f"Nmap service detection failed for {port_key}: {e}")
                    results[port_key] = {
                        'service': 'unknown',
                        'version': '',
                        'confidence': 0,
                        'status': 'error'
                    }

    except Exception as e:
        logger.error(f"Parallel service detection executor failed: {e}")

    logger.info(f"Parallel nmap scan completed for {len(results)} ports")
    return results


def run_nmap_vuln_detection(
    host: str,
    port: int,
    service: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Run nmap NSE vulnerability detection scripts for a specific service.

    Args:
        host: Target hostname/IP
        port: Port number to scan
        service: Service name (mysql, postgresql, redis, ssh, etc.)
        timeout: Timeout in seconds for NSE scripts

    Returns:
        Dictionary containing:
        {
            'vulnerabilities': [
                {'cve_id': 'CVE-2012-2122', 'severity': 'critical', 'cvss': 9.8},
                ...
            ],
            'status': 'success' | 'timeout' | 'no_vulns' | 'error'
        }

    Example:
        >>> result = run_nmap_vuln_detection('example.com', 3306, 'mysql')
        >>> result['vulnerabilities']
        [{'cve_id': 'CVE-2012-2122', 'severity': 'critical', 'cvss': 9.8}]
    """
    try:
        vuln_scripts = {
            'mysql': 'mysql-vuln*,mysql-enum',
            'postgresql': 'postgresql-vuln*',
            'mongodb': 'mongodb-enum',
            'redis': 'redis-info',
            'ftp': 'ftp-anon',
            'smtp': 'smtp-enum',
            'ssh': 'ssh2-enum-algos',
            'http': 'http-vuln*',
            'https': 'http-vuln*',
        }

        scripts = vuln_scripts.get(service.lower(), 'vuln')
        nmap_cmd = config.get('tools.nmap.path', 'nmap')

        cmd = [
            nmap_cmd,
            '-sV',
            '--script=' + scripts,
            '-p', str(port),
            '--script-timeout', str(timeout),
            '-oX', '-',
            host
        ]

        logger.debug(f"Running vulnerability detection on {host}:{port} for {service}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10
        )

        vulnerabilities = _extract_cves_from_nmap_output(result.stdout)

        if vulnerabilities:
            return {
                'vulnerabilities': vulnerabilities,
                'status': 'success'
            }
        else:
            return {
                'vulnerabilities': [],
                'status': 'no_vulns'
            }

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap vuln detection timed out for {host}:{port}")
        return {
            'vulnerabilities': [],
            'status': 'timeout'
        }
    except FileNotFoundError:
        raise Exception("Nmap not found. Install from: https://nmap.org/download.html")
    except Exception as e:
        logger.error(f"Vulnerability detection failed for {host}:{port}: {e}")
        return {
            'vulnerabilities': [],
            'status': 'error'
        }


def run_nmap_vuln_detection_parallel(
    ports_with_services: List[Tuple[str, int, str]],
    max_workers: int = 3
) -> Dict[str, Dict[str, Any]]:
    """
    Run nmap NSE vulnerability detection in parallel for multiple services.

    Args:
        ports_with_services: List of (host, port, service) tuples
        max_workers: Number of concurrent nmap processes (default: 3)

    Returns:
        Dictionary mapping "host:port" keys to vulnerability results

    Example:
        >>> ports = [('example.com', 3306, 'mysql')]
        >>> results = run_nmap_vuln_detection_parallel(ports)
        >>> results['example.com:3306']['vulnerabilities']
        [{'cve_id': 'CVE-2012-2122', ...}]
    """
    results = {}

    if not ports_with_services:
        return results

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for host, port, service in ports_with_services:
                port_key = f"{host}:{port}"
                future = executor.submit(
                    run_nmap_vuln_detection,
                    host=host,
                    port=port,
                    service=service,
                    timeout=30
                )
                futures[future] = port_key
                logger.debug(f"Submitted vulnerability scan for {port_key} ({service})")

            for future in as_completed(futures.keys()):
                port_key = futures[future]
                try:
                    result = future.result(timeout=40)
                    results[port_key] = result
                    logger.debug(f"Nmap vuln detection completed for {port_key}: {len(result.get('vulnerabilities', []))} CVEs")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Nmap vulnerability detection timed out for {port_key}")
                    results[port_key] = {
                        'vulnerabilities': [],
                        'status': 'timeout'
                    }
                except Exception as e:
                    logger.error(f"Nmap vulnerability detection failed for {port_key}: {e}")
                    results[port_key] = {
                        'vulnerabilities': [],
                        'status': 'error'
                    }

    except Exception as e:
        logger.error(f"Parallel vulnerability detection executor failed: {e}")

    logger.info(f"Parallel vulnerability scan completed for {len(results)} ports")
    return results


__all__ = [
    'run_nmap_service_detection',
    'run_nmap_service_detection_parallel',
    'run_nmap_vuln_detection',
    'run_nmap_vuln_detection_parallel',
    '_parse_nmap_xml',
    '_extract_cves_from_nmap_output',
]
