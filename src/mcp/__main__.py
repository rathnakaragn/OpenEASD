"""
OpenEASD MCP Server entry point.

Run with:
    python -m src.mcp

Or with fastmcp:
    fastmcp run src.mcp.server:mcp
"""

from src.mcp.server import mcp

if __name__ == "__main__":
    mcp.run()
