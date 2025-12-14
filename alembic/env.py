"""
Alembic Environment Configuration for OpenEASD.

This module configures Alembic to work with SQLModel and the OpenEASD
database schema. It supports both online and offline migration modes.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlmodel import SQLModel

from alembic import context

# Import all models to ensure they're registered with SQLModel.metadata
# This is required for Alembic autogenerate to detect model changes
from src.data.models.domain import Domain
from src.data.models.scan import ScanSession
from src.data.models.subdomain import SubdomainHistory
from src.data.models.tool_results import (
    SubfinderResult,
    AmassResult,
    NmapResult,
    NaabuResult
)
from src.data.models.finding import (
    Finding,
    Vulnerability,
    CVEMapping,
    FindingGroup
)
from src.data.models.job import Job

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set SQLModel metadata for autogenerate support
target_metadata = SQLModel.metadata


def get_database_url() -> str:
    """
    Get database URL from environment or config.

    Priority:
    1. OPENEASD_DATABASE_URL environment variable
    2. alembic.ini sqlalchemy.url
    3. Default: sqlite:///data/openeasd.db
    """
    # Check environment variable first
    db_url = os.environ.get('OPENEASD_DATABASE_URL')
    if db_url:
        return db_url

    # Fall back to alembic.ini setting
    return config.get_main_option("sqlalchemy.url", "sqlite:///data/openeasd.db")


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLModel compatibility options
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate
    a connection with the context.
    """
    # Override the sqlalchemy.url with our computed value
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # SQLModel compatibility options
            compare_type=True,
            compare_server_default=True,
            # Render SQL for nullable columns correctly
            render_as_batch=True,  # Required for SQLite ALTER TABLE support
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
