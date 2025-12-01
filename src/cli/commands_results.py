"""
Results module for OpenEASD CLI.

Handles viewing scan results and scan listings.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from typing import Dict, Any

from src.data.database.sqlmodel_manager import SQLModelManager


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
