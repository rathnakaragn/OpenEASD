"""
Core interfaces for OpenEASD API layer.

These interfaces define the contracts for the modular architecture,
enabling easy testing, mocking, and implementation swapping.
"""

from .database import DatabaseManager
from .scanner import SecurityScanner, SecurityTool

__all__ = ['DatabaseManager', 'SecurityScanner', 'SecurityTool']