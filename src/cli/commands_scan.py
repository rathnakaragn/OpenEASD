"""
Scan orchestration module for OpenEASD CLI.

Handles multi-tool scan workflows using the service layer.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
Updated: December 2025 (refactored to use CLIContext)
"""

from typing import Dict, Any

from src.cli.context import CLIContext, cli_command
from src.utils.validation import validate_domain
from src.utils.timezone import get_ist_now


@cli_command
def scan_command(ctx: CLIContext, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute passive subdomain enumeration scan using the service layer.

    Args:
        ctx: CLI context with services
        args: Parsed command arguments with keys:
            - domain: Target domain to scan
            - timeout: Optional timeout in seconds
            - save: Whether to save results (default: True)

    Returns:
        Scan results dictionary containing:
            - scan_id: Unique scan identifier
            - domain: Scanned domain
            - subdomains: List of discovered subdomains
            - active_subdomains: List of active subdomains
            - open_ports: List of open ports found
            - summary: Statistics summary

    Raises:
        ValueError: If domain format is invalid
    """
    domain = validate_domain(args['domain'])
    timeout = args.get('timeout')

    print(f"[*] Starting passive subdomain enumeration for: {domain}")
    print()

    # Execute scan through service layer
    # This handles: tool execution, storage, analysis, and domain scan count updates
    result = ctx.scan_service.execute_scan(domain, timeout=timeout)

    scan_id = result.get('scan_id')
    subdomains = result.get('subdomains', [])
    active_subdomains = result.get('active_subdomains', [])
    ports_found = result.get('ports_found', [])

    print(f"[*] Scan ID: {scan_id}")
    print()
    print(f"[+] Found {len(subdomains)} subdomains")
    print(f"[+] Found {len(active_subdomains)} active subdomains")
    print(f"[+] Found {len(ports_found)} open ports")

    if result.get('analysis'):
        findings_count = result['analysis'].get('findings_count', 0)
        print(f"[+] Analysis findings: {findings_count}")

    print()

    # Build subdomain_ips mapping from active_subdomains
    # Note: Full IP mapping is handled internally by the service
    subdomain_ips = {}
    for subdomain in active_subdomains:
        # Find IP from ports_found for this subdomain
        for port_info in ports_found:
            if port_info.get('host') == subdomain or port_info.get('subdomain') == subdomain:
                ip = port_info.get('ip', '')
                if ip:
                    if subdomain not in subdomain_ips:
                        subdomain_ips[subdomain] = []
                    if ip not in subdomain_ips[subdomain]:
                        subdomain_ips[subdomain].append(ip)

    # Return results in expected format
    return {
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
        },
        'analysis': result.get('analysis')
    }


@cli_command
def batch_scan_subfinder_command(ctx: CLIContext, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute batch subfinder scan for all domains using the service layer.

    Args:
        ctx: CLI context with services
        args: Parsed command arguments with keys:
            - timeout: Optional timeout in seconds
            - primary: Scan only primary domains (default: False)

    Returns:
        Batch scan results dictionary containing:
            - success: Whether batch completed
            - scans: List of individual scan results
            - total_domains: Number of domains scanned
            - successful_scans: Count of successful scans
            - failed_scans: Count of failed scans
    """
    # Get all domains using service layer
    primary_only = args.get('primary', False)
    result = ctx.domain_service.list_domains(limit=1000, primary_only=primary_only)
    domains = result.get('domains', [])

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

    print(f"[*] Starting batch scan using service layer")
    print(f"[*] Found {len(domains)} domain(s) to scan")
    if primary_only:
        print(f"[*] Scanning primary domains only")
    print()

    # Prepare scan results
    scan_results = []
    successful_scans = 0
    failed_scans = 0
    timeout = args.get('timeout')

    # Scan each domain using the scan service
    for idx, domain_obj in enumerate(domains, 1):
        domain = domain_obj.domain if hasattr(domain_obj, 'domain') else domain_obj.get('domain')
        print(f"[{idx}/{len(domains)}] Scanning: {domain}")
        print("-" * 60)

        try:
            # Execute scan through service layer
            # This handles: tool execution, storage, analysis, and domain scan count updates
            result = ctx.scan_service.execute_scan(domain, timeout=timeout)

            scan_results.append({
                'domain': domain,
                'status': 'success',
                'scan_id': result.get('scan_id'),
                'subdomains': result.get('subdomain_count', 0),
                'active_subdomains': result.get('active_count', 0),
                'open_ports': result.get('ports_count', 0),
                'analysis': result.get('analysis')
            })

            successful_scans += 1
            print(f"[+] Scan completed: {domain}")
            print(f"    Subdomains: {result.get('subdomain_count', 0)}")
            print(f"    Active: {result.get('active_count', 0)}")
            print(f"    Ports: {result.get('ports_count', 0)}")

            if result.get('analysis'):
                print(f"    Analysis findings: {result['analysis'].get('findings_count', 0)}")

        except Exception as e:
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
