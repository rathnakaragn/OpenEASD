"""
Tool runner functions for OpenEASD.

This module consolidates the functions that execute external security tools
like subfinder, naabu, dnsx, httpx, and nmap by calling them as subprocesses.
"""
import subprocess
import json
import tempfile
import os
import logging
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils.config import Config
from src.utils.validation import validate_domain, validate_domains

logger = logging.getLogger(__name__)

config = Config()

def run_subfinder(domain: str, timeout: int = None) -> List[str]:
    """
    Run subfinder to discover subdomains.
    """
    domain = validate_domain(domain)
    if timeout is None:
        timeout = config.get('subfinder.timeout', 300)
    try:
        result = subprocess.run(
            [config.get('tools.subfinder.path', 'subfinder'), '-d', domain, '-silent', '-json'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        subdomains = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.append(data['host'])
                except json.JSONDecodeError:
                    continue
        return subdomains
    except subprocess.TimeoutExpired:
        raise Exception(f"Subfinder timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("Subfinder not found. Please install: https://github.com/projectdiscovery/subfinder")

def run_naabu(targets: List[str], top_ports: int = None, timeout: int = None) -> List[Dict[str, Any]]:
    """
    Run naabu to scan ports.
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
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name
        
        result = subprocess.run(
            [config.get('tools.naabu.path', 'naabu'), '-list', targets_file, '-top-ports', str(top_ports), '-json', '-silent'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        ports = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    ports.append({
                        'subdomain': data.get('host', ''),
                        'port': data.get('port', 0),
                        'protocol': data.get('protocol', 'tcp'),
                        'ip': data.get('ip', '')
                    })
                except json.JSONDecodeError:
                    continue
        return ports
    except subprocess.TimeoutExpired:
        raise Exception(f"Naabu timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("Naabu not found. Please install: https://github.com/projectdiscovery/naabu")
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)

def run_dnsx(domains: List[str], record_types: List[str] = None, timeout: int = None) -> List[Dict[str, Any]]:
    """
    Run dnsx to perform DNS queries.
    """
    if not domains:
        return []
    domains = validate_domains(domains)
    if timeout is None:
        timeout = config.get('workflow.default_timeout', 300)
    domains_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for domain in domains:
                f.write(f"{domain}\n")
            domains_file = f.name
        cmd = [config.get('tools.dnsx.path', 'dnsx'), '-l', domains_file, '-json', '-silent', '-resp']
        if record_types:
            for rtype in record_types:
                rtype_lower = rtype.lower()
                if rtype_lower in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'ptr', 'soa', 'srv']:
                    cmd.append(f'-{rtype_lower}')
        else:
            cmd.append('-a')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        records = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    def normalize_records(record_list):
                        if not record_list: return []
                        return [str(item) if not isinstance(item, dict) else str(item) for item in record_list]
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
                except json.JSONDecodeError:
                    continue
        return records
    except subprocess.TimeoutExpired:
        raise Exception(f"dnsx timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("dnsx not found. Please install: https://github.com/projectdiscovery/dnsx")
    finally:
        if domains_file and Path(domains_file).exists():
            Path(domains_file).unlink(missing_ok=True)

def run_httpx(targets: List[str], threads: int = None, timeout: int = None) -> List[Dict[str, Any]]:
    """
    Run httpx to probe HTTP/HTTPS services.
    """
    if not targets:
        return []
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
        pdtm_path = os.path.expanduser('~/.pdtm/go/bin/httpx')
        if os.path.exists(pdtm_path):
            httpx_cmd = pdtm_path
        else:
            httpx_cmd = config.get('tools.httpx.path', 'httpx')
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name
        result = subprocess.run(
            [httpx_cmd, '-l', targets_file, '-json', '-silent', '-status-code', '-content-length', '-title', '-tech-detect', '-server', '-threads', str(threads)],
            capture_output=True, text=True, timeout=timeout
        )
        probes = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
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
                except json.JSONDecodeError:
                    continue
        return probes
    except subprocess.TimeoutExpired:
        raise Exception(f"httpx timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("httpx not found. Please install: https://github.com/projectdiscovery/httpx")
    finally:
        if targets_file and Path(targets_file).exists():
            Path(targets_file).unlink(missing_ok=True)


def _parse_nmap_xml(xml_output: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Parse nmap XML output to extract service information.

    Expected XML format:
    <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" version="5.7.30-0-log" conf="95" product="MySQL"/>
    </port>

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


def run_nmap_service_detection(
    host: str,
    port: int,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Use nmap -sV to identify service type and version.

    Performs service version detection on a specific port to identify
    what service is running and its version.

    Args:
        host: Target hostname/IP
        port: Port number to scan
        timeout: Timeout in seconds

    Returns:
        Dictionary containing:
        {
            'service': 'mysql',              # Service name
            'version': '5.7.30-0-log',       # Version string
            'confidence': 95,                # 0-100 confidence level
            'product': 'MySQL',              # Product name
            'extrainfo': '0-log',            # Extra information
            'os_family': '',                 # OS family if detected
            'status': 'success'              # success, timeout, no_match, or error
        }

    Raises:
        FileNotFoundError: If nmap is not installed

    Examples:
        >>> result = run_nmap_service_detection('example.com', 3306, timeout=10)
        >>> result['service']
        'mysql'
        >>> result['version']
        '5.7.30-0-log'
        >>> result['confidence']
        95
    """
    try:
        # Validate input
        validate_domain(host)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")

        # Get nmap path from config
        nmap_cmd = config.get('tools.nmap.path', 'nmap')

        # Build nmap command with XML output
        cmd = [
            nmap_cmd,
            '-sV',                          # Service version detection
            '--version-all',                # Aggressively detect versions
            '-p', str(port),                # Specific port
            '--script-timeout', str(timeout),
            '-oX', '-',                     # XML output to stdout
            host
        ]

        logger.debug(f"Running nmap service detection on {host}:{port}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5  # Add buffer for processing
        )

        # Parse XML output
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

    Executes nmap -sV on multiple ports concurrently using ThreadPoolExecutor.
    Results are processed as they complete (not in submission order).

    Args:
        ports_to_scan: List of (host, port) tuples to scan
        max_workers: Number of concurrent nmap processes (default: 5)

    Returns:
        Dictionary mapping "host:port" keys to service detection results:
        {
            "example.com:3306": {
                'service': 'mysql',
                'version': '5.7.30',
                'confidence': 95,
                'status': 'success'
            },
            ...
        }

    Examples:
        >>> ports = [('example.com', 3306), ('example.com', 5432)]
        >>> results = run_nmap_service_detection_parallel(ports, max_workers=5)
        >>> results['example.com:3306']['service']
        'mysql'
    """
    from concurrent.futures import as_completed

    results = {}

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all nmap tasks
            futures = {}
            for host, port in ports_to_scan:
                port_key = f"{host}:{port}"
                future = executor.submit(
                    run_nmap_service_detection,
                    host=host,
                    port=port,
                    timeout=10
                )
                futures[future] = port_key  # Map future to port_key

            # Process results AS THEY COMPLETE (not sequentially)
            # This is the key difference - as_completed() returns futures as they finish
            for future in as_completed(futures.keys()):
                port_key = futures[future]
                try:
                    result = future.result(timeout=15)  # 15s = 10s nmap + 5s buffer
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
        # Return empty dict - caller will handle gracefully
        pass

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

    Uses nmap's NSE scripts to detect known vulnerabilities in the service.
    Service-specific scripts are selected based on the detected service.

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
            'has_authentication': bool,
            'status': 'success' | 'timeout' | 'no_vulns' | 'error'
        }

    Examples:
        >>> result = run_nmap_vuln_detection('example.com', 3306, 'mysql')
        >>> result['vulnerabilities']
        [{'cve_id': 'CVE-2012-2122', 'severity': 'critical', 'cvss': 9.8}]
    """
    try:
        # Service-specific vulnerability scripts
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

        # Get scripts for service
        scripts = vuln_scripts.get(service.lower(), 'vuln')

        # Get nmap path from config
        nmap_cmd = config.get('tools.nmap.path', 'nmap')

        # Build nmap command with NSE scripts
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
            timeout=timeout + 10  # Add buffer for processing
        )

        # Parse results
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


def _extract_cves_from_nmap_output(nmap_output: str) -> List[Dict[str, Any]]:
    """
    Extract CVE information from nmap NSE vulnerability output.

    Uses CVESeverityService for severity/CVSS mapping.

    Args:
        nmap_output: Raw nmap script output text

    Returns:
        List of CVE dictionaries sorted by CVSS score (highest first):
        [
            {'cve_id': 'CVE-2012-2122', 'severity': 'critical', 'cvss': 9.8, ...},
            {'cve_id': 'CVE-2016-6663', 'severity': 'high', 'cvss': 7.5, ...},
        ]
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
                'cvss': severity_info.get('cvss', 5.0),  # Default to 5.0 if missing
                'description': severity_info.get('description', 'Known vulnerability'),
                'affected_versions': severity_info.get('affected_versions', [])
            })

        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x['cvss'], reverse=True)

    except Exception as e:
        logger.error(f"Error extracting CVEs from nmap output: {e}")

    return cves


def run_nmap_vuln_detection_parallel(
    ports_with_services: List[Tuple[str, int, str]],
    max_workers: int = 3
) -> Dict[str, Dict[str, Any]]:
    """
    Run nmap NSE vulnerability detection in parallel for multiple services.

    Executes service-specific nmap vulnerability scripts concurrently.
    Results are processed as they complete (not in submission order).

    Args:
        ports_with_services: List of (host, port, service) tuples
        max_workers: Number of concurrent nmap processes (default: 3)

    Returns:
        Dictionary mapping "host:port" keys to vulnerability results
    """
    from concurrent.futures import as_completed

    results = {}

    if not ports_with_services:
        return results

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all vulnerability detection tasks
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

            # Process results AS THEY COMPLETE
            for future in as_completed(futures.keys()):
                port_key = futures[future]
                try:
                    result = future.result(timeout=40)  # 40s = 30s nmap + 10s buffer
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
        pass

    logger.info(f"Parallel vulnerability scan completed for {len(results)} ports")
    return results