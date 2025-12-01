"""
Tool runner functions for OpenEASD.

This module consolidates the functions that execute external security tools
like subfinder, naabu, dnsx, and httpx by calling them as subprocesses.
"""
import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any

from src.utils.config import Config
from src.utils.validation import validate_domain, validate_domains

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