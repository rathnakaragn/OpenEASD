"""
OpenEASD MCP (Model Context Protocol) Server.

Exposes OpenEASD security scanning capabilities to AI assistants
via the Model Context Protocol.

Usage:
    # Run MCP server
    python -m src.mcp

    # Or via fastmcp CLI
    fastmcp run src.mcp.server:mcp
"""

from src.mcp.server import mcp

__all__ = ['mcp']
