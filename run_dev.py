#!/usr/bin/env python3
"""
OpenEASD FastAPI Development Server Startup Script

Usage:
    python run_dev.py [OPTIONS]

OPTIONS:
    --host HOST          Server host (default: 0.0.0.0)
    --port PORT          Server port (default: 8000)
    --reload             Auto-reload on code changes (enabled by default)
    --no-reload          Disable auto-reload
    --workers N          Number of workers (default: 1 for dev)
    --log-level LEVEL    Log level: critical, error, warning, info, debug (default: info)
    --help               Show this help message
"""

import sys
import subprocess
import argparse
import os
from pathlib import Path

# ANSI Colors
class Colors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header():
    """Print startup header"""
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"{Colors.HEADER}{'='*60}")
    print(f"  OpenEASD FastAPI Development Server")
    print(f"{'='*60}{Colors.ENDC}")
    print()

def print_config(host, port, reload_enabled, workers, log_level):
    """Print configuration details"""
    print(f"{Colors.OKGREEN}Configuration:{Colors.ENDC}")
    print(f"  Host:        {Colors.WARNING}{host}{Colors.ENDC}")
    print(f"  Port:        {Colors.WARNING}{port}{Colors.ENDC}")
    print(f"  Auto-reload: {Colors.WARNING}{'Enabled' if reload_enabled else 'Disabled'}{Colors.ENDC}")
    print(f"  Workers:     {Colors.WARNING}{workers}{Colors.ENDC}")
    print(f"  Log Level:   {Colors.WARNING}{log_level}{Colors.ENDC}")
    print()

def check_uv():
    """Check if uv is installed"""
    result = subprocess.run(['uv', '--version'], capture_output=True)
    if result.returncode != 0:
        print(f"{Colors.FAIL}❌ Error: 'uv' command not found{Colors.ENDC}")
        print("Please install uv first: https://docs.astral.sh/uv/")
        sys.exit(1)

def check_dependencies():
    """Check and install dependencies if needed"""
    print(f"{Colors.WARNING}Checking dependencies...{Colors.ENDC}")
    venv_path = Path('.venv')

    if not venv_path.exists():
        print(f"{Colors.WARNING}Installing dependencies with uv sync...{Colors.ENDC}")
        result = subprocess.run(['uv', 'sync'])
        if result.returncode != 0:
            print(f"{Colors.FAIL}Error: Failed to install dependencies{Colors.ENDC}")
            sys.exit(1)
    else:
        print(f"{Colors.OKGREEN}✓ Virtual environment found{Colors.ENDC}")

def print_startup_info(host, port):
    """Print startup information"""
    print()
    print(f"{Colors.OKGREEN}Starting FastAPI server...{Colors.ENDC}")
    print()
    print(f"{Colors.HEADER}API Documentation: http://{host}:{port}/api/docs{Colors.ENDC}")
    print(f"{Colors.HEADER}Alternative Docs:  http://{host}:{port}/api/redoc{Colors.ENDC}")
    print(f"{Colors.HEADER}OpenAPI Schema:    http://{host}:{port}/openapi.json{Colors.ENDC}")
    print()
    print(f"{Colors.WARNING}Press Ctrl+C to stop the server{Colors.ENDC}")
    print()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='OpenEASD FastAPI Development Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_dev.py                           # Run with defaults
  python run_dev.py --port 8001               # Run on port 8001
  python run_dev.py --host 127.0.0.1          # Run on localhost only
  python run_dev.py --no-reload                # Disable auto-reload
  python run_dev.py --log-level debug          # Enable debug logging
  python run_dev.py --port 8001 --no-reload   # Multiple options
        """
    )

    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Server host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Server port (default: 8000)'
    )
    parser.add_argument(
        '--reload/--no-reload',
        default=True,
        help='Auto-reload on code changes (default: enabled)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=1,
        help='Number of workers (default: 1 for dev)'
    )
    parser.add_argument(
        '--log-level',
        default='info',
        choices=['critical', 'error', 'warning', 'info', 'debug'],
        help='Log level (default: info)'
    )

    args = parser.parse_args()

    # Print header
    print_header()

    # Check prerequisites
    check_uv()
    check_dependencies()

    # Print configuration
    print_config(args.host, args.port, args.reload, args.workers, args.log_level)

    # Print startup info
    print_startup_info(args.host, args.port)

    # Build uvicorn command
    cmd = [
        'uv', 'run', 'uvicorn',
        'src.api.main:app',
        '--host', args.host,
        '--port', str(args.port),
        '--log-level', args.log_level,
        '--workers', str(args.workers),
    ]

    if args.reload:
        cmd.append('--reload')

    # Start the server
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Server stopped by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}Error: Failed to start the server: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
