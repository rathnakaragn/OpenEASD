"""
Domain management commands for OpenEASD CLI.

Handles adding, listing, updating, removing, and showing apex domains.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

from typing import Optional, Dict, Any
import click
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.exceptions import DomainAlreadyExists, InvalidDomainFormat, DomainNotFound, CliCommandError
from src.cli.formatters import format_json_with_datetime


def domain_add_command(domain: str, primary: bool, contact: Optional[str], frequency: Optional[str]) -> Dict[str, Any]:
    """
    Add an apex domain.

    Args:
        domain: The domain name to add.
        primary: Whether the domain is a primary domain.
        contact: The contact email for the domain.
        frequency: The scan frequency for the domain.
    """
    db_manager = SQLModelManager()
    db_manager.initialize()
    service = DomainService(db_manager)

    try:
        new_domain = service.create_domain(
            domain=domain,
            is_primary=primary,
            contact_email=contact,
            scan_frequency=frequency
        )
        return {
            'success': True,
            'message': f'✓ Added domain {new_domain.domain}',
            'domain': new_domain
        }
    except (DomainAlreadyExists, InvalidDomainFormat) as e:
        raise CliCommandError(str(e))
    finally:
        db_manager.close()


def domain_list_command(limit: int, primary: bool, details: bool, output: str) -> Dict[str, Any]:
    """
    List all apex domains.

    Args:
        limit: The maximum number of domains to list.
        primary: Whether to list only primary domains.
        details: Whether to show detailed information for each domain.
        output: The output format.
    """
    db_manager = SQLModelManager()
    db_manager.initialize()
    service = DomainService(db_manager)

    try:
        result = service.list_domains(
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
    finally:
        db_manager.close()


def domain_update_command(domain: str, primary: Optional[bool]) -> Dict[str, Any]:
    """
    Update domain metadata.

    Args:
        domain: The domain name to update.
        primary: The new primary status.
    """
    db_manager = SQLModelManager()
    db_manager.initialize()
    service = DomainService(db_manager)

    try:
        updated_domain = service.update_domain(
            domain=domain,
            is_primary=primary
        )
        return {
            'success': True,
            'message': f'✓ Updated domain {updated_domain.domain}',
            'updated_fields': ['is_primary'] if primary is not None else []
        }
    except (DomainNotFound, InvalidDomainFormat, ValueError) as e:
        raise CliCommandError(str(e))
    finally:
        db_manager.close()


def domain_remove_command(domain: str, force: bool) -> Dict[str, Any]:
    """
    Remove a domain.

    Args:
        domain: The domain name to remove.
        force: Whether to force the deletion without confirmation.
    """
    db_manager = SQLModelManager()
    db_manager.initialize()
    service = DomainService(db_manager)

    try:
        if not force:
            confirm = input(f"\nAre you sure you want to delete {domain} and all its data? Type 'yes' to confirm: ")
            if confirm.lower() != 'yes':
                click.echo('Domain deletion cancelled')
                return {'success': False, 'message': 'Domain deletion cancelled'}

        result = service.delete_domain(domain=domain)
        return result

    except (DomainNotFound, InvalidDomainFormat) as e:
        raise CliCommandError(str(e))
    finally:
        db_manager.close()