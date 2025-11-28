"""
HTTPX tool module for OpenEASD CLI.
"""
from typing import Dict, Any

from src.tools.runners import run_httpx

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
