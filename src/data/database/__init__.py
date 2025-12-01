"""
Database layer for OpenEASD.

Provides SQLModel implementation with SQLite for single-user MVP.
"""

from .sqlmodel_manager import SQLModelManager

__all__ = ['SQLModelManager']
