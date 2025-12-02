"""
CLI context management for OpenEASD.

Provides centralized dependency management and exception handling
for all CLI commands using Click's context system.
"""

import sys
import functools
import click
from typing import Callable, Any

from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.findings_service import FindingsService, FindingNotFound, InvalidFindingStatus
from src.services.exceptions import (
    DomainAlreadyExists,
    InvalidDomainFormat,
    DomainNotFound,
    ScanNotFound,
    CliCommandError
)


class CLIContext:
    """
    Centralized CLI context for managing services and database connections.

    Usage:
        with CLIContext() as ctx:
            domains = ctx.domain_service.list_domains()
    """

    def __init__(self):
        self._db_manager = None
        self._domain_service = None
        self._scan_service = None
        self._findings_service = None

    def __enter__(self):
        """Initialize database connection on context entry."""
        self._db_manager = SQLModelManager()
        self._db_manager.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close database connection on context exit."""
        if self._db_manager:
            self._db_manager.close()
        return False

    @property
    def db(self) -> SQLModelManager:
        """Get the database manager."""
        if self._db_manager is None:
            raise RuntimeError("CLIContext must be used within a 'with' block")
        return self._db_manager

    @property
    def domain_service(self) -> DomainService:
        """Get or create domain service (lazy initialization)."""
        if self._domain_service is None:
            self._domain_service = DomainService(self.db)
        return self._domain_service

    @property
    def scan_service(self) -> ScanService:
        """Get or create scan service (lazy initialization)."""
        if self._scan_service is None:
            self._scan_service = ScanService(self.db, enable_analysis=True)
        return self._scan_service

    @property
    def findings_service(self) -> FindingsService:
        """Get or create findings service (lazy initialization)."""
        if self._findings_service is None:
            self._findings_service = FindingsService(self.db)
        return self._findings_service


def cli_command(func: Callable) -> Callable:
    """
    Decorator for CLI commands that provides:
    - Automatic CLIContext management (db init/cleanup)
    - Centralized exception handling

    Usage:
        @cli_command
        def my_command(ctx: CLIContext, arg1, arg2):
            result = ctx.domain_service.list_domains()
            return result
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            with CLIContext() as ctx:
                return func(ctx, *args, **kwargs)
        except KeyboardInterrupt:
            click.echo("\n\nOperation cancelled by user", err=True)
            sys.exit(130)
        except CliCommandError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except DomainNotFound as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except DomainAlreadyExists as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except InvalidDomainFormat as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except ScanNotFound as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except FindingNotFound as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except InvalidFindingStatus as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    return wrapper
