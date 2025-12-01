"""
Results and history module for OpenEASD CLI.

Handles viewing scan history, results, and scan listings.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from typing import Dict, Any
from datetime import datetime

from src.data.database.sqlmodel_manager import SQLModelManager


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
        for domain_obj in domains_result.get('domains', []):
            domain = domain_obj.domain
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

        if not scans:
            return {
                'message': 'No scan history found'
            }

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

        # Get subfinder results (subdomains) for this scan
        subfinder_result = db_manager.get_tool_results(args['scan_id'], 'subfinder', limit=10000)
        subfinder_results = subfinder_result.get('results', [])

        # Get naabu results (ports) for this scan
        naabu_result = db_manager.get_tool_results(args['scan_id'], 'naabu', limit=10000)
        naabu_results = naabu_result.get('results', [])

        # Build subdomains list
        subdomains = []
        for result in subfinder_results:
            subdomains.append({
                'subdomain': result.get('subdomain', ''),
                'ip_address': '',
                'discovered_at': result.get('discovered_at', '')
            })

        # Build ports list
        ports = []
        for result in naabu_results:
            ports.append({
                'subdomain': result.get('target_host', ''),
                'port': result.get('port', 0),
                'protocol': result.get('protocol', 'tcp'),
                'ip': result.get('ip', ''),
                'discovered_at': result.get('discovered_at', '')
            })

        scan_data = {
            'subdomains': subdomains,
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
