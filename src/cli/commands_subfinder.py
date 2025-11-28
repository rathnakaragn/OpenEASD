"""
Subfinder tool module for OpenEASD CLI.
"""
from typing import Dict, Any

from src.tools.runners import run_subfinder

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
