"""
DNSX tool module for OpenEASD CLI.
"""
from typing import Dict, Any

from src.tools.runners import run_dnsx

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
