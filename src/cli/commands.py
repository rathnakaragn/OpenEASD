"""CLI command implementations."""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.timezone import get_ist_now
from src.utils.config import Config
from src.utils.validation import validate_domain, validate_domains

config = Config()

def run_subfinder(domain: str, timeout: int = None) -> List[str]:
    """
    Run subfinder to discover subdomains.

    Args:
        domain: Domain to scan
        timeout: Command timeout in seconds

    Returns:
        List of discovered subdomains

    Raises:
        ValueError: If domain format is invalid
    """
    # Validate domain to prevent command injection
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

    Args:
        targets: List of hosts to scan
        top_ports: Number of top ports to scan
        timeout: Command timeout in seconds

    Returns:
        List of port dictionaries

    Raises:
        ValueError: If any target domain format is invalid
    """
    if not targets:
        return []

    # Validate all targets to prevent command injection
    targets = validate_domains(targets)

    if top_ports is None:
        top_ports = config.get('naabu.top_ports', 1000)
    if timeout is None:
        timeout = config.get('naabu.timeout', 300)

    try:
        # Write targets to temp file
        import tempfile
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

        # Clean up temp file
        Path(targets_file).unlink(missing_ok=True)

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


def run_dnsx(domains: List[str], record_types: List[str] = None, timeout: int = None) -> List[Dict[str, Any]]:
    """
    Run dnsx to perform DNS queries.

    Args:
        domains: List of domains/subdomains to query
        record_types: DNS record types to query (a, aaaa, cname, mx, ns, txt, etc.)
        timeout: Command timeout in seconds

    Returns:
        List of DNS record dictionaries

    Raises:
        ValueError: If any domain format is invalid
    """
    if not domains:
        return []

    # Validate all domains to prevent command injection
    domains = validate_domains(domains)

    if timeout is None:
        timeout = config.get('workflow.default_timeout', 300)

    try:
        # Write domains to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for domain in domains:
                f.write(f"{domain}\n")
            domains_file = f.name

        # Build dnsx command
        cmd = [config.get('tools.dnsx.path', 'dnsx'), '-l', domains_file, '-json', '-silent', '-resp']

        # Add record type flags
        if record_types:
            for rtype in record_types:
                rtype_lower = rtype.lower()
                if rtype_lower in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'ptr', 'soa', 'srv']:
                    cmd.append(f'-{rtype_lower}')
        else:
            # Default to A records if none specified
            cmd.append('-a')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Clean up temp file
        Path(domains_file).unlink(missing_ok=True)

        records = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)

                    # Helper function to convert record values to strings
                    def normalize_records(record_list):
                        if not record_list:
                            return []
                        normalized = []
                        for item in record_list:
                            if isinstance(item, dict):
                                # For complex records like MX, SOA, SRV - convert to string
                                normalized.append(str(item))
                            else:
                                normalized.append(str(item))
                        return normalized

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


def run_httpx(targets: List[str], threads: int = None, timeout: int = None) -> List[Dict[str, Any]]:
    """
    Run httpx to probe HTTP/HTTPS services.

    Args:
        targets: List of URLs/hosts to probe
        threads: Number of concurrent threads
        timeout: Command timeout in seconds

    Returns:
        List of HTTP probe result dictionaries

    Raises:
        ValueError: If any target domain format is invalid
    """
    if not targets:
        return []

    # Validate all targets to prevent command injection
    # Note: targets can be URLs (http://example.com) or domains
    validated_targets = []
    for target in targets:
        # Strip protocol if present for validation
        domain = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        validate_domain(domain)
        validated_targets.append(target)
    targets = validated_targets

    if threads is None:
        threads = config.get('httpx.threads', 50)
    if timeout is None:
        timeout = config.get('workflow.default_timeout', 300)

    try:
        # Find ProjectDiscovery httpx binary
        import os

        # Check common locations for ProjectDiscovery httpx
        pdtm_path = os.path.expanduser('~/.pdtm/go/bin/httpx')

        if os.path.exists(pdtm_path):
            httpx_cmd = pdtm_path
        else:
            # Try other locations or fallback
            httpx_cmd = config.get('tools.httpx.path', 'httpx')

        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        result = subprocess.run(
            [
                httpx_cmd,
                '-l', targets_file,
                '-json',
                '-silent',
                '-status-code',
                '-content-length',
                '-title',
                '-tech-detect',
                '-server',
                '-threads', str(threads)
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Clean up temp file
        Path(targets_file).unlink(missing_ok=True)

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



def scan_command(args) -> Dict[str, Any]:
    """
    Execute passive subdomain enumeration scan.

    Args:
        args: Parsed command arguments

    Returns:
        Scan results dictionary

    Raises:
        ValueError: If domain format is invalid
    """
    domain = validate_domain(args['domain'])
    timeout = args.get('timeout')
    save = args.get('save', False)

    print(f"[*] Starting passive subdomain enumeration for: {domain}")
    print()

    # Initialize storage if saving
    db_manager = None
    scan_id = None

    if save:
        # Initialize database manager
        db_manager = SQLModelManager()
        db_manager.initialize()

        scan_id = db_manager.create_scan_session('passive_subdomain_enum', [domain])
        print(f"[*] Scan ID: {scan_id}")
        print()

    try:
        # Step 1: Passive subdomain discovery with subfinder
        print("[*] Step 1/3: Discovering subdomains (subfinder)...")
        subdomains = run_subfinder(domain, timeout)
        print(f"[+] Found {len(subdomains)} subdomains")
        print()

        # Step 2: DNS resolution to find active subdomains
        active_subdomains = []
        subdomain_ips = {}

        if subdomains:
            print(f"[*] Step 2/3: Resolving subdomains (dnsx)...")
            dns_records = run_dnsx(subdomains, record_types=['a'], timeout=timeout)

            for record in dns_records:
                if record.get('a'):  # Has A records - subdomain is active
                    host = record['host']
                    active_subdomains.append(host)
                    subdomain_ips[host] = record['a']

            print(f"[+] Found {len(active_subdomains)} active subdomains")
            print()

        # Step 3: Port scanning on active subdomains
        ports_found = []
        if active_subdomains:
            print(f"[*] Step 3/3: Scanning ports (naabu)...")
            ports_found = run_naabu(active_subdomains, timeout=timeout)
            print(f"[+] Found {len(ports_found)} open ports")
            print()

        # Add domain to database if saving (skip if already exists)
        if save and db_manager:
            domain_exists = db_manager.domain_exists(domain)
            if not domain_exists:
                db_manager.add_domain(domain, is_primary=True)

        # Save results and update scan status
        if save and db_manager and scan_id:
            # Store subdomains as findings
            alerts = []

            # Add subdomain discoveries
            for subdomain in subdomains:
                is_active = subdomain in active_subdomains
                alerts.append({
                    'domain': subdomain,
                    'scan_id': scan_id,
                    'vulnerability_type': 'subdomain_discovered',
                    'severity': 'info',
                    'description': f"Subdomain discovered: {subdomain} ({'active' if is_active else 'inactive'})",
                    'tool_source': 'subfinder',
                    'discovered_at': get_ist_now()
                })

            # Add port scan findings
            for port_info in ports_found:
                subdomain = port_info['subdomain']
                port = port_info['port']
                alerts.append({
                    'domain': subdomain,
                    'scan_id': scan_id,
                    'vulnerability_type': 'open_port',
                    'severity': 'low' if port in [80, 443] else 'medium',
                    'description': f"Open port {port}/{port_info['protocol']} on {subdomain} (IP: {port_info.get('ip', 'N/A')})",
                    'tool_source': 'naabu',
                    'discovered_at': get_ist_now()
                })

            if alerts:
                db_manager.store_alerts(alerts)

            db_manager.update_scan_status(
                scan_id,
                'completed',
                end_time=get_ist_now(),
                findings_count=len(alerts)
            )

        # Return results
        result = {
            'type': 'scan_results',
            'scan_id': scan_id,
            'domain': domain,
            'timestamp': get_ist_now().isoformat(),
            'subdomains': subdomains,
            'active_subdomains': active_subdomains,
            'subdomain_ips': subdomain_ips,
            'open_ports': ports_found,
            'summary': {
                'total_subdomains': len(subdomains),
                'active_subdomains': len(active_subdomains),
                'open_ports': len(ports_found)
            }
        }

        return result

    except Exception as e:
        if save and db_manager and scan_id:
            db_manager.update_scan_status(
                scan_id,
                'failed',
                end_time=get_ist_now()
            )
        raise

    finally:
        if db_manager:
            db_manager.close()


def history_command(args) -> Dict[str, Any]:
    """
    Execute history command - shows scan history.

    Args:
        args: Parsed command arguments

    Returns:
        Scan history dictionary
    """
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        # Get all domains
        domains_result = db_manager.get_domains(limit=1000)

        # Get scan history
        scans_result = db_manager.get_scan_history(limit=1000)

        # Build summary per domain
        domain_summary = {}
        for domain_info in domains_result.get('domains', []):
            domain = domain_info['domain']
            domain_summary[domain] = {
                'domain': domain,
                'scan_count': 0,
                'total_subdomains': 0,
                'first_scan': None,
                'last_scan': None,
                'status': 'pending'
            }

        # Aggregate scan data
        for scan in scans_result.get('scans', []):
            domains_scanned = scan.get('domains_scanned', [])
            for domain in domains_scanned:
                if domain not in domain_summary:
                    domain_summary[domain] = {
                        'domain': domain,
                        'scan_count': 0,
                        'total_subdomains': 0,
                        'first_scan': None,
                        'last_scan': None,
                        'status': 'pending'
                    }

                summary = domain_summary[domain]
                summary['scan_count'] += 1

                if scan.get('status') == 'completed':
                    summary['total_subdomains'] = max(summary['total_subdomains'], scan.get('findings_count', 0))

                scan_time = scan.get('start_time')
                if scan_time is not None:
                    if summary['first_scan'] is None or scan_time < summary['first_scan']:
                        summary['first_scan'] = scan_time
                    if summary['last_scan'] is None or scan_time > summary['last_scan']:
                        summary['last_scan'] = scan_time
                        summary['status'] = scan.get('status', 'pending')

        # Convert to list and sort
        scans = list(domain_summary.values())
        # Sort by last_scan datetime, putting None values at the end
        scans.sort(key=lambda x: x['last_scan'] if x['last_scan'] else datetime.min, reverse=True)

        # Limit results
        scans = scans[:args['limit']]

        # Format for output
        for scan in scans:
            scan['total_ports'] = scan['total_subdomains']  # For compatibility
            # Convert datetime objects to strings
            if scan['first_scan'] is not None:
                scan['first_scan'] = scan['first_scan'].isoformat()
            else:
                scan['first_scan'] = 'N/A'
            if scan['last_scan'] is not None:
                scan['last_scan'] = scan['last_scan'].isoformat()
            else:
                scan['last_scan'] = 'N/A'

        return {
            'type': 'history',
            'scans': scans
        }

    finally:
        db_manager.close()


def results_command(args) -> Dict[str, Any]:
    """
    Execute results command - shows results for a specific scan.

    Args:
        args: Parsed command arguments

    Returns:
        Scan results dictionary
    """
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        # Get scan info
        scan_info = db_manager.get_scan_status(args['scan_id'])

        if not scan_info:
            raise Exception(f"Scan ID not found: {args['scan_id']}")

        # Get alerts (subdomains/ports) for this scan
        alerts_result = db_manager.get_alerts(scan_id=args['scan_id'], limit=10000)
        alerts = alerts_result.get('alerts', [])

        ports = []
        subdomains = set()
        for alert in alerts:
            subdomain = alert.get('domain', '')
            subdomains.add(subdomain)

            # Parse port from description (e.g., "Open port 80 (tcp)")
            port_num = 0
            protocol = 'tcp'
            desc = alert.get('description', '')
            if 'Open port' in desc:
                parts = desc.replace('Open port ', '').split(' ')
                try:
                    port_num = int(parts[0])
                    if len(parts) > 1:
                        protocol = parts[1].strip('()')
                except:
                    pass

            if port_num > 0:  # Only add if we found a valid port
                ports.append({
                    'subdomain': subdomain,
                    'port': port_num,
                    'protocol': protocol,
                    'ip': '',
                    'discovered_at': alert.get('discovered_at', '')
                })

        scan_data = {
            'subdomains': [{'subdomain': s, 'ip_address': '', 'discovered_at': ''} for s in sorted(subdomains)],
            'ports': ports
        }

        # Extract first domain from domains_scanned
        domains_scanned = scan_info.get('domains_scanned', [])
        domain = domains_scanned[0] if domains_scanned else ''

        return {
            'type': 'scan_results',
            'scan': {
                'scan_id': scan_info['scan_id'],
                'domain': domain,
                'start_time': scan_info['start_time'].isoformat() if scan_info['start_time'] else '',
                'end_time': scan_info['end_time'].isoformat() if scan_info['end_time'] else '',
                'status': scan_info['status'],
                'total_subdomains': len(scan_data['subdomains']),
                'total_ports': scan_info['findings_count']
            },
            'subdomains': scan_data['subdomains'],
            'ports': scan_data['ports']
        }

    finally:
        db_manager.close()


def view_scans_command(args) -> Dict[str, Any]:
    """
    Execute view scans command - lists all scan IDs.

    Args:
        args: Parsed command arguments

    Returns:
        Scan list dictionary
    """
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        # Use database manager method instead of raw SQL
        result = db_manager.get_scan_history(limit=args['limit'])

        scans = []
        for scan in result.get('scans', []):
            # Extract first domain from domains_scanned
            domains = scan.get('domains_scanned', [])
            domain = domains[0] if domains else 'N/A'

            # Convert datetime objects to strings
            start_time = scan.get('start_time')
            end_time = scan.get('end_time')

            scans.append({
                'scan_id': scan.get('scan_id'),
                'scan_type': scan.get('scan_type'),
                'tool_name': scan.get('tool_name'),
                'domain': domain,
                'status': scan.get('status'),
                'findings_count': scan.get('findings_count', 0),
                'start_time': start_time.isoformat() if start_time else 'N/A',
                'end_time': end_time.isoformat() if end_time else 'N/A'
            })

        return {
            'type': 'scan_list',
            'scans': scans
        }

    finally:
        db_manager.close()


def batch_scan_subfinder_command(args) -> Dict[str, Any]:
    """
    Execute batch subfinder scan for all domains.

    Args:
        args: Parsed command arguments

    Returns:
        Batch scan results dictionary
    """
    db_manager = SQLModelManager()
    db_manager.initialize()

    try:
        # Get all domains (optionally filter by primary)
        primary_only = args.get('primary', False)

        result = db_manager.get_domains(
            limit=1000,  # Large limit to get all domains
            primary_only=primary_only
        )

        domains = result['domains']

        if not domains:
            return {
                'success': True,
                'type': 'batch_scan',
                'message': 'No domains found',
                'scans': [],
                'total_domains': 0,
                'successful_scans': 0,
                'failed_scans': 0
            }

        print(f"[*] Starting batch subfinder scan")
        print(f"[*] Found {len(domains)} domain(s) to scan")
        if primary_only:
            print(f"[*] Scanning primary domains only")
        print()

        # Prepare scan results
        scan_results = []
        successful_scans = 0
        failed_scans = 0
        timeout = args.get('timeout')

        # Scan each domain
        for idx, domain_info in enumerate(domains, 1):
            domain = domain_info['domain']
            print(f"[{idx}/{len(domains)}] Scanning: {domain}")
            print("-" * 60)

            # Create a new scan session for this domain
            scan_id = None

            try:
                # Create scan session
                try:
                    scan_id = db_manager.create_scan_session(
                        scan_type='passive_subdomain_enum',
                        domains=[domain],
                        tool_name='subfinder'
                    )
                    print(f"[*] Scan ID: {scan_id}")
                    print()
                except Exception as e:
                    raise Exception(f"Failed to create scan session: {e}")

                # Step 1: Run subfinder
                try:
                    print("[*] Step 1/3: Discovering subdomains (subfinder)...")
                    subdomains = run_subfinder(domain, timeout)
                    print(f"[+] Found {len(subdomains)} subdomains")
                    print()
                except Exception as e:
                    raise Exception(f"Failed to run subfinder: {e}")

                # Step 2: DNS resolution to find active subdomains
                active_subdomains = []
                subdomain_ips = {}

                if subdomains:
                    try:
                        print(f"[*] Step 2/3: Resolving subdomains (dnsx)...")
                        dns_records = run_dnsx(subdomains, record_types=['a'], timeout=timeout)

                        for record in dns_records:
                            if record.get('a'):
                                host = record['host']
                                active_subdomains.append(host)
                                subdomain_ips[host] = record['a']

                        print(f"[+] Found {len(active_subdomains)} active subdomains")
                        print()
                    except Exception as e:
                        print(f"[!] Warning: dnsx failed: {e}")
                        print()

                # Step 3: Port scanning on active subdomains
                ports_found = []
                if active_subdomains:
                    try:
                        print(f"[*] Step 3/3: Scanning ports (naabu)...")
                        ports_found = run_naabu(active_subdomains, timeout=timeout)
                        print(f"[+] Found {len(ports_found)} open ports")
                        print()
                    except Exception as e:
                        print(f"[!] Warning: naabu failed: {e}")
                        print()

                # Ensure domain exists in database
                try:
                    domain_exists = db_manager.domain_exists(domain)
                    if not domain_exists:
                        db_manager.add_domain(domain, is_primary=domain_info.get('is_primary', False))
                except Exception as e:
                    raise Exception(f"Failed to add domain: {e}")

                # Store subdomains in tool-specific table (detailed)
                try:
                    subfinder_results = []
                    for subdomain in subdomains:
                        subfinder_results.append({
                            'scan_id': scan_id,
                            'apex_domain': domain,
                            'subdomain': subdomain,
                            'source': 'subfinder',
                            'discovered_at': get_ist_now(),
                            'raw_json': None
                        })

                    if subfinder_results:
                        db_manager.store_subfinder_results(subfinder_results)
                        print(f"[*] Stored {len(subfinder_results)} subfinder results")
                except Exception as e:
                    raise Exception(f"Failed to store subfinder results: {e}")

                # Store subdomains as alerts (summary)
                try:
                    alerts = []

                    # Add subdomain discoveries
                    for subdomain in subdomains:
                        is_active = subdomain in active_subdomains
                        alerts.append({
                            'domain': subdomain,
                            'scan_id': scan_id,
                            'vulnerability_type': 'subdomain_discovered',
                            'severity': 'info',
                            'description': f"Subdomain discovered: {subdomain} ({'active' if is_active else 'inactive'})",
                            'tool_source': 'subfinder',
                            'discovered_at': get_ist_now()
                        })

                    # Add port scan findings
                    for port_info in ports_found:
                        subdomain = port_info['subdomain']
                        port = port_info['port']
                        alerts.append({
                            'domain': subdomain,
                            'scan_id': scan_id,
                            'vulnerability_type': 'open_port',
                            'severity': 'low' if port in [80, 443] else 'medium',
                            'description': f"Open port {port}/{port_info['protocol']} on {subdomain} (IP: {port_info.get('ip', 'N/A')})",
                            'tool_source': 'naabu',
                            'discovered_at': get_ist_now()
                        })

                    if alerts:
                        db_manager.store_alerts(alerts)
                        print(f"[*] Stored {len(alerts)} security alerts")
                except Exception as e:
                    raise Exception(f"Failed to store alerts: {e}")

                # Update scan status
                try:
                    db_manager.update_scan_status(
                        scan_id,
                        'completed',
                        end_time=get_ist_now(),
                        findings_count=len(subdomains)
                    )
                except Exception as e:
                    raise Exception(f"Failed to update scan status: {e}")

                scan_results.append({
                    'domain': domain,
                    'status': 'success',
                    'scan_id': scan_id,
                    'subdomains': len(subdomains),
                    'active_subdomains': len(active_subdomains),
                    'open_ports': len(ports_found)
                })

                successful_scans += 1
                print(f"[+] Scan completed: {domain}")

            except Exception as e:
                # Update scan status to failed if scan_id exists
                if scan_id:
                    try:
                        db_manager.update_scan_status(
                            scan_id,
                            'failed',
                            end_time=get_ist_now()
                        )
                    except:
                        pass

                scan_results.append({
                    'domain': domain,
                    'status': 'failed',
                    'error': str(e)
                })

                failed_scans += 1
                print(f"[-] Scan failed: {domain} - {str(e)}")

            print()

        # Return results after scanning all domains
        return {
            'success': True,
            'type': 'batch_scan',
            'scans': scan_results,
            'total_domains': len(domains),
            'successful_scans': successful_scans,
            'failed_scans': failed_scans
        }

    finally:
        db_manager.close()


def run_tool_subfinder_command(args) -> Dict[str, Any]:
    """
    Run subfinder tool directly.

    Args:
        args: Command arguments with domain and timeout

    Returns:
        Dictionary with scan results
    """
    try:
        domain = args['domain']
        timeout = args.get('timeout')
        print(f"[*] Running subfinder on: {domain}")
        print()

        # Run subfinder
        subdomains = run_subfinder(domain, timeout=timeout)

        if not subdomains:
            return {
                'success': True,
                'message': 'No subdomains found',
                'domain': domain,
                'tool': 'subfinder',
                'subdomain_count': 0,
                'subdomains': []
            }

        print(f"[+] Found {len(subdomains)} subdomains\n")

        return {
            'success': True,
            'domain': domain,
            'tool': 'subfinder',
            'subdomain_count': len(subdomains),
            'subdomains': sorted(subdomains)
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'domain': args.get('domain', 'unknown'),
            'tool': 'subfinder'
        }


def run_tool_naabu_command(args) -> Dict[str, Any]:
    """
    Run naabu tool directly.

    Args:
        args: Command arguments with targets, top_ports, and timeout

    Returns:
        Dictionary with port scan results
    """
    try:
        targets = args['targets']
        top_ports = args['top_ports']
        timeout = args['timeout']
        
        targets = targets if isinstance(targets, list) else [targets]

        print(f"[*] Running naabu on {len(targets)} target(s)")
        print(f"[*] Scanning top {top_ports} ports")
        print()

        # Run naabu
        ports = run_naabu(targets, top_ports=top_ports, timeout=timeout)

        if not ports:
            return {
                'success': True,
                'message': 'No open ports found',
                'tool': 'naabu',
                'targets': targets,
                'port_count': 0,
                'ports': []
            }

        print(f"[+] Found {len(ports)} open ports\n")

        return {
            'success': True,
            'tool': 'naabu',
            'targets': targets,
            'port_count': len(ports),
            'ports': ports
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'tool': 'naabu'
        }


def run_tool_dnsx_command(args) -> Dict[str, Any]:
    """
    Run dnsx tool directly.

    Args:
        args: Command arguments with domains, record_types, and timeout

    Returns:
        Dictionary with DNS query results
    """
    try:
        domains = args['domains']
        record_types = args.get('record_types')
        timeout = args['timeout']

        domains = domains if isinstance(domains, list) else [domains]
        
        print(f"[*] Running dnsx on {len(domains)} domain(s)")
        if record_types:
            print(f"[*] Querying record types: {', '.join(record_types).upper()}")
        else:
            print(f"[*] Querying record types: A (default)")
        print()

        # Run dnsx
        records = run_dnsx(domains, record_types=record_types, timeout=timeout)

        if not records:
            return {
                'success': True,
                'message': 'No DNS records found',
                'tool': 'dnsx',
                'domains': domains,
                'record_count': 0,
                'records': []
            }

        print(f"[+] Resolved {len(records)} domain(s)\n")

        return {
            'success': True,
            'tool': 'dnsx',
            'domains': domains,
            'record_count': len(records),
            'records': records
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'tool': 'dnsx'
        }


def run_tool_httpx_command(args) -> Dict[str, Any]:
    """
    Run httpx tool directly.

    Args:
        args: Command arguments with targets, threads, and timeout

    Returns:
        Dictionary with HTTP probe results
    """
    try:
        targets = args['targets']
        threads = args.get('threads', 50)
        timeout = args['timeout']

        targets = targets if isinstance(targets, list) else [targets]

        print(f"[*] Running httpx on {len(targets)} target(s)")
        print(f"[*] Using {threads} threads")
        print()

        # Run httpx
        probes = run_httpx(targets, threads=threads, timeout=timeout)

        if not probes:
            return {
                'success': True,
                'message': 'No HTTP services found',
                'tool': 'httpx',
                'targets': targets,
                'probe_count': 0,
                'probes': []
            }

        print(f"[+] Probed {len(probes)} HTTP service(s)\n")

        return {
            'success': True,
            'tool': 'httpx',
            'targets': targets,
            'probe_count': len(probes),
            'probes': probes
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'tool': 'httpx'
        }