#!/usr/bin/env python3
"""
OpenEASD CLI entry point.

Usage:
    python openeasd.py scan example.com
    python openeasd.py history
    python openeasd.py results <scan-id>
"""

from src.cli.main import main

if __name__ == '__main__':
    main()
