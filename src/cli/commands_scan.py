"""
Scan orchestration module for OpenEASD CLI.

Handles multi-tool scan workflows with database storage.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from typing import Dict, Any

from src.tools.runners import run_subfinder, run_dnsx, run_naabu
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.timezone import get_ist_now
from src.utils.validation import validate_domain


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
            # Import analysis layer alert service
            from src.analysis.alert_service import AlertManagementService
            alert_service = AlertManagementService(db_manager)

            # Store subdomains and ports as findings through analysis layer
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
                    'port': port,
                    'protocol': port_info['protocol'],
                    'discovered_at': get_ist_now()
                })

            if alerts:
                # Convert alerts to findings using analysis layer
                findings = alert_service.create_alert_batch(scan_id, alerts)
                alert_service.store_alerts(findings)

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
        for idx, domain_obj in enumerate(domains, 1):
            domain = domain_obj['domain']
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
                        db_manager.add_domain(domain, is_primary=domain_obj['is_primary'])
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

                # Store naabu port scan results
                try:
                    naabu_results = []
                    ips_found = 0
                    for port_info in ports_found:
                        host = port_info.get('subdomain', port_info.get('host', ''))
                        # Use IP from naabu, fallback to dnsx mapping, then empty string
                        naabu_ip = port_info.get('ip', '')
                        dnsx_ip = (subdomain_ips.get(host, [''])[0] if subdomain_ips.get(host) else '')
                        ip = naabu_ip or dnsx_ip
                        if ip:
                            ips_found += 1
                        naabu_results.append({
                            'scan_id': scan_id,
                            'target_host': host,
                            'port': port_info.get('port'),
                            'protocol': port_info.get('protocol', 'tcp'),
                            'ip': ip,
                            'discovered_at': get_ist_now()
                        })

                    if naabu_results:
                        db_manager.store_naabu_results(naabu_results)
                        print(f"[*] Stored {len(naabu_results)} naabu results")
                except Exception as e:
                    raise Exception(f"Failed to store naabu results: {e}")

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
