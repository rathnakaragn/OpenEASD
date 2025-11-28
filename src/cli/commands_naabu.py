"""
Naabu tool module for OpenEASD CLI.
"""
from typing import Dict, Any

from src.tools.runners import run_naabu

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
