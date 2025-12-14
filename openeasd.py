#!/usr/bin/env python3
"""
OpenEASD API Server Entry Point.

Usage:
    python openeasd.py                    # Start API server (default port 8000)
    python openeasd.py --port 8080        # Start on custom port
    python openeasd.py --reload           # Start with auto-reload (dev mode)

API Documentation:
    http://localhost:8000/docs            # Swagger UI
    http://localhost:8000/redoc           # ReDoc

Worker (run in separate terminal):
    python -m workers.scan_worker
"""

import argparse
import uvicorn


def main():
    """Start the OpenEASD API server."""
    parser = argparse.ArgumentParser(
        description="OpenEASD - Open Source External Attack Surface Detection API"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("OpenEASD API Server")
    print("=" * 50)
    print(f"Starting server on http://{args.host}:{args.port}")
    print(f"API Docs: http://localhost:{args.port}/docs")
    print()
    print("NOTE: Start the worker in a separate terminal:")
    print("  python -m workers.scan_worker")
    print("=" * 50)

    uvicorn.run(
        "src.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == '__main__':
    main()
