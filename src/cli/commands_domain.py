"""
Domain management commands for OpenEASD CLI.

Handles adding, listing, updating, removing, and showing apex domains.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

from typing import Optional, Dict, Any
import click
from src.cli.context import CLIContext, cli_command
from src.cli.formatters import format_json_with_datetime


@cli_command
def domain_add_command(
    ctx: CLIContext,
    domain: str,
    primary: bool,
    contact: Optional[str],
    frequency: Optional[str]
) -> Dict[str, Any]:
    """
    Add an apex domain.

    Args:
        ctx: CLI context with services
        domain: The domain name to add.
        primary: Whether the domain is a primary domain.
        contact: The contact email for the domain.
        frequency: The scan frequency for the domain.
    """
    new_domain = ctx.domain_service.create_domain(
        domain=domain,
        is_primary=primary,
        contact_email=contact,
        scan_frequency=frequency
    )
    return {
        'success': True,
        'message': f'Added domain {new_domain.domain}',
        'domain': new_domain
    }


@cli_command
def domain_list_command(
    ctx: CLIContext,
    limit: int,
    primary: bool,
    details: bool,
    output: str
) -> Dict[str, Any]:
    """
    List all apex domains.

    Args:
        ctx: CLI context with services
        limit: The maximum number of domains to list.
        primary: Whether to list only primary domains.
        details: Whether to show detailed information for each domain.
        output: The output format.
    """
    result = ctx.domain_service.list_domains(
        limit=limit,
        primary_only=primary
    )

    return {
        'success': True,
        'domains': [domain.model_dump() for domain in result['domains']],
        'total_count': result['total_count'],
        'has_more': result['has_more'],
        'show_details': details
    }


@cli_command
def domain_update_command(
    ctx: CLIContext,
    domain: str,
    primary: Optional[bool]
) -> Dict[str, Any]:
    """
    Update domain metadata.

    Args:
        ctx: CLI context with services
        domain: The domain name to update.
        primary: The new primary status.
    """
    updated_domain = ctx.domain_service.update_domain(
        domain=domain,
        is_primary=primary
    )
    return {
        'success': True,
        'message': f'Updated domain {updated_domain.domain}',
        'updated_fields': ['is_primary'] if primary is not None else []
    }


@cli_command
def domain_remove_command(
    ctx: CLIContext,
    domain: str,
    force: bool
) -> Dict[str, Any]:
    """
    Remove a domain.

    Args:
        ctx: CLI context with services
        domain: The domain name to remove.
        force: Whether to force the deletion without confirmation.
    """
    if not force:
        if not click.confirm(f"Delete {domain} and all its data?", default=False):
            return {'success': False, 'message': 'Domain deletion cancelled'}

    result = ctx.domain_service.delete_domain(domain=domain)
    return result
