"""
Domain management commands for OpenEASD CLI.

Handles adding, listing, updating, removing, and showing apex domains.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

import asyncio
from typing import Optional, List, Dict, Any

from src.data.database.organization_manager import OrganizationManager
from src.data.database.duckdb_manager import DuckDBManager
from src.utils.config import Config


def domain_add_command(args) -> Dict[str, Any]:
    """
    Add an apex domain to the current organization.

    Args:
        args: Command arguments with domain, primary, notes, tags, contact, frequency
    """
    async def _add_domain():
        # Get current organization from config
        config = Config()
        organization = config.get_default_organization()

        if not organization:
            return {
                'success': False,
                'message': 'No default organization set. Use: openeasd org set <organization>'
            }

        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Check if organization exists
            org_exists = await org_manager.organization_exists(organization)
            if not org_exists:
                # Create organization if it doesn't exist
                await org_manager.create_organization(organization)

            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Check if domain already exists
                exists = await db_manager.domain_exists(args.domain)
                if exists:
                    return {
                        'success': False,
                        'message': f'Domain {args.domain} already exists in {organization}'
                    }

                # Parse tags if provided
                tags = None
                if hasattr(args, 'tags') and args.tags:
                    tags = [tag.strip() for tag in args.tags.split(',')]

                # Add domain
                result = await db_manager.add_domain(
                    domain=args.domain,
                    domain_type='apex',
                    is_primary=args.primary if hasattr(args, 'primary') else False,
                    notes=args.notes if hasattr(args, 'notes') else None,
                    tags=tags,
                    contact_email=args.contact if hasattr(args, 'contact') else None,
                    scan_frequency=args.frequency if hasattr(args, 'frequency') else None,
                    active_scan_enabled=True
                )

                return {
                    'success': True,
                    'message': f'✓ Added domain {args.domain} to {organization}',
                    'domain': result
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_add_domain())


def domain_list_command(args) -> Dict[str, Any]:
    """
    List all apex domains for the current organization.

    Args:
        args: Command arguments with limit, type, primary filters
    """
    async def _list_domains():
        # Get current organization from config
        config = Config()
        organization = config.get_default_organization()

        if not organization:
            return {
                'success': False,
                'message': 'No default organization set. Use: openeasd org set <organization>'
            }

        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Check if organization exists
            org_exists = await org_manager.organization_exists(organization)
            if not org_exists:
                return {
                    'success': True,
                    'message': f'No domains found for {organization}',
                    'domains': [],
                    'total_count': 0
                }

            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Get domains with filters
                domain_type = getattr(args, 'type', None)
                primary_only = getattr(args, 'primary', False)
                limit = getattr(args, 'limit', 20)

                result = await db_manager.get_domains(
                    limit=limit,
                    domain_type=domain_type,
                    primary_only=primary_only
                )

                return {
                    'success': True,
                    'organization': organization,
                    'domains': result['domains'],
                    'total_count': result['total_count'],
                    'has_more': result['has_more']
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_list_domains())


def domain_update_command(args) -> Dict[str, Any]:
    """
    Update domain metadata.

    Args:
        args: Command arguments with domain and fields to update
    """
    async def _update_domain():
        # Get current organization from config
        config = Config()
        organization = config.get_default_organization()

        if not organization:
            return {
                'success': False,
                'message': 'No default organization set. Use: openeasd org set <organization>'
            }

        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)
            if not db_path:
                return {
                    'success': False,
                    'message': f'Organization {organization} not found'
                }

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Check if domain exists
                exists = await db_manager.domain_exists(args.domain)
                if not exists:
                    return {
                        'success': False,
                        'message': f'Domain {args.domain} not found in {organization}'
                    }

                # Build update kwargs
                update_fields = {}

                if hasattr(args, 'primary') and args.primary is not None:
                    update_fields['is_primary'] = args.primary

                if hasattr(args, 'notes') and args.notes:
                    update_fields['notes'] = args.notes

                if hasattr(args, 'tags') and args.tags:
                    update_fields['tags'] = [tag.strip() for tag in args.tags.split(',')]

                if hasattr(args, 'contact') and args.contact:
                    update_fields['contact_email'] = args.contact

                if hasattr(args, 'frequency') and args.frequency:
                    update_fields['scan_frequency'] = args.frequency

                if hasattr(args, 'active_scan') and args.active_scan is not None:
                    update_fields['active_scan_enabled'] = args.active_scan

                if not update_fields:
                    return {
                        'success': False,
                        'message': 'No fields provided to update'
                    }

                # Update domain
                result = await db_manager.update_domain(args.domain, **update_fields)

                return {
                    'success': result['success'],
                    'message': f'✓ Updated domain {args.domain}',
                    'updated_fields': list(update_fields.keys())
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_update_domain())


def domain_remove_command(args) -> Dict[str, Any]:
    """
    Remove a domain from the current organization.

    Args:
        args: Command arguments with domain and force flag
    """
    async def _remove_domain():
        # Get current organization from config
        config = Config()
        organization = config.get_default_organization()

        if not organization:
            return {
                'success': False,
                'message': 'No default organization set. Use: openeasd org set <organization>'
            }

        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)
            if not db_path:
                return {
                    'success': False,
                    'message': f'Organization {organization} not found'
                }

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Check if domain exists
                exists = await db_manager.domain_exists(args.domain)
                if not exists:
                    return {
                        'success': False,
                        'message': f'Domain {args.domain} not found in {organization}'
                    }

                # Get deletion preview
                preview = await db_manager.get_deletion_preview(domain=args.domain)

                # Confirm deletion if not forced
                if not args.force:
                    totals = preview.get('totals', {})

                    print(f"\n{'=' * 60}")
                    print(f"Domain Deletion Preview")
                    print(f"{'=' * 60}")
                    print(f"Domain: {args.domain}")
                    print(f"Organization: {organization}")
                    print()
                    print("Data to be deleted:")
                    print(f"  Scan Sessions:        {totals.get('scan_sessions', 0):>6}")
                    print(f"  Security Alerts:      {totals.get('security_alerts', 0):>6}")
                    print()
                    print("Tool-specific Results:")
                    print(f"  Subfinder Results:    {totals.get('subfinder_results', 0):>6}")
                    print(f"  Amass Results:        {totals.get('amass_results', 0):>6}")
                    print(f"  Nmap Results:         {totals.get('nmap_results', 0):>6}")
                    print(f"  Naabu Results:        {totals.get('naabu_results', 0):>6}")
                    print()
                    print("Tool-specific History:")
                    print(f"  Subfinder History:    {totals.get('subfinder_history', 0):>6}")
                    print(f"  Amass History:        {totals.get('amass_history', 0):>6}")
                    print(f"  Nmap History:         {totals.get('nmap_history', 0):>6}")
                    print(f"  Naabu History:        {totals.get('naabu_history', 0):>6}")
                    print(f"  Subdomain History:    {totals.get('subdomain_history', 0):>6}")
                    print(f"{'-' * 60}")
                    print(f"  TOTAL RECORDS:        {totals.get('total_records', 0):>6}")
                    print(f"{'=' * 60}")
                    print()
                    print("⚠️  WARNING: This action cannot be undone!")

                    confirm = input("\nType 'yes' to confirm deletion: ")
                    if confirm.lower() != 'yes':
                        return {
                            'success': False,
                            'message': 'Domain deletion cancelled'
                        }

                # Delete domain and all associated data
                deleted = await db_manager.delete_domain_with_data(args.domain)

                return {
                    'success': True,
                    'message': f'✓ Deleted domain {args.domain}',
                    'deleted': deleted
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_remove_domain())


def domain_show_command(args) -> Dict[str, Any]:
    """
    Show detailed information about a specific domain.

    Args:
        args: Command arguments with domain name
    """
    async def _show_domain():
        # Get current organization from config
        config = Config()
        organization = config.get_default_organization()

        if not organization:
            return {
                'success': False,
                'message': 'No default organization set. Use: openeasd org set <organization>'
            }

        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)
            if not db_path:
                return {
                    'success': False,
                    'message': f'Organization {organization} not found'
                }

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Check if domain exists
                exists = await db_manager.domain_exists(args.domain)
                if not exists:
                    return {
                        'success': False,
                        'message': f'Domain {args.domain} not found in {organization}'
                    }

                # Get domain details
                result = await db_manager.get_domains(limit=1)
                domain_info = None

                for domain in result['domains']:
                    if domain['domain'] == args.domain:
                        domain_info = domain
                        break

                if not domain_info:
                    return {
                        'success': False,
                        'message': f'Could not retrieve details for {args.domain}'
                    }

                # Get subdomain history
                history = await db_manager.get_subdomain_history(args.domain, limit=10)

                # Get recent scans
                # Note: This would require additional database query
                # For now, we'll use the scan_count from domain info

                return {
                    'success': True,
                    'organization': organization,
                    'domain': domain_info,
                    'subdomain_count': history['total_count'],
                    'recent_subdomains': history['history'][:5]  # Top 5 recent
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_show_domain())
