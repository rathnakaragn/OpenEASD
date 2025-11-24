"""
Database layer for OpenEASD.

Provides DuckDB implementation for single-user MVP.
"""

from .duckdb_manager import DuckDBManager

__all__ = ['DuckDBManager']