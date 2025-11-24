"""
Domain management commands for OpenEASD CLI.

Handles adding, listing, updating, removing, and showing apex domains.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

from typing import Optional, List, Dict, Any

from src.data.database.duckdb_manager import DuckDBManager
from src.utils.validation import validate_domain


def domain_add_command(args) -> Dict[str, Any]:
    """
    Add an apex domain.

    Args:
        args: Command arguments with domain, primary, notes, tags, contact, frequency
    """
    db_manager = DuckDBManager()
    db_manager.initialize()

    try:
        # Validate domain to prevent injection attacks
        domain = validate_domain(args['domain'])

        # Check if domain already exists
        exists = db_manager.domain_exists(domain)
        if exists:
            return {
                'success': False,
                'message': f'Domain {domain} already exists'
            }

        # Parse tags if provided
        tags = None
        if args.get('tags'):
            tags = [tag.strip() for tag in args['tags'].split(',')]

        # Add domain
        result = db_manager.add_domain(
            domain=domain,
            domain_type='apex',
            is_primary=args.get('primary', False),
            notes=args.get('notes'),
            tags=tags,
            contact_email=args.get('contact'),
            scan_frequency=args.get('frequency'),
            active_scan_enabled=True
        )

        return {
            'success': True,
            'message': f'✓ Added domain {domain}',
            'domain': result
        }

    finally:
        db_manager.close()


def domain_list_command(args) -> Dict[str, Any]:
    """
    List all apex domains.

    Args:
        args: Command arguments with limit, type, primary filters
    """
    db_manager = DuckDBManager()
    db_manager.initialize()

    try:
        # Get domains with filters
        domain_type = args.get('domain_type')
        primary_only = args.get('primary', False)
        limit = args.get('limit', 20)

        result = db_manager.get_domains(
            limit=limit,
            domain_type=domain_type,
            primary_only=primary_only
        )

        return {
            'success': True,
            'domains': result['domains'],
            'total_count': result['total_count'],
            'has_more': result['has_more']
        }

    finally:
        db_manager.close()


def domain_update_command(args) -> Dict[str, Any]:
    """
    Update domain metadata.

    Args:
        args: Command arguments with domain and fields to update
    """
    db_manager = DuckDBManager()
    db_manager.initialize()

    try:
        # Validate domain to prevent injection attacks
        domain = validate_domain(args['domain'])

        # Check if domain exists
        exists = db_manager.domain_exists(domain)
        if not exists:
            return {
                'success': False,
                'message': f'Domain {domain} not found'
            }

        # Build update kwargs
        update_fields = {}

        if args.get('primary') is not None:
            update_fields['is_primary'] = args['primary']

        if args.get('notes'):
            update_fields['notes'] = args['notes']

        if args.get('tags'):
            update_fields['tags'] = [tag.strip() for tag in args['tags'].split(',')]

        if not update_fields:
            return {
                'success': False,
                'message': 'No fields provided to update. Use --primary, --notes, or --tags'
            }

        # Update domain
        result = db_manager.update_domain(domain, **update_fields)

        return {
            'success': result['success'],
            'message': f'✓ Updated domain {domain}',
            'updated_fields': list(update_fields.keys())
        }

    finally:
        db_manager.close()


def domain_remove_command(args) -> Dict[str, Any]:
    """
    Remove a domain.

    Args:
        args: Command arguments with domain and force flag
    """
    db_manager = DuckDBManager()
    db_manager.initialize()

    try:
        # Validate domain to prevent injection attacks
        domain = validate_domain(args['domain'])
        force = args.get('force', False)

        # Check if domain exists
        exists = db_manager.domain_exists(domain)
        if not exists:
            return {
                'success': False,
                'message': f'Domain {domain} not found'
            }

        # Get deletion preview
        preview = db_manager.get_deletion_preview(domain)

        # Confirm deletion if not forced
        if not force:
            totals = preview.get('totals', {})

            print(f"\n{'=' * 60}")
            print(f"Domain Deletion Preview")
            print(f"{'=' * 60}")
            print(f"Domain: {domain}")
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
        deleted = db_manager.delete_domain_with_data(domain)

        return {
            'success': True,
            'message': f'✓ Deleted domain {domain}',
            'deleted': deleted
        }

    finally:
        db_manager.close()


def domain_show_command(args) -> Dict[str, Any]:
    """
    Show detailed information about a specific domain.

    Args:
        args: Command arguments with domain name
    """
    db_manager = DuckDBManager()
    db_manager.initialize()

    try:
        # Validate domain to prevent injection attacks
        domain = validate_domain(args['domain'])

        # Check if domain exists
        exists = db_manager.domain_exists(domain)
        if not exists:
            return {
                'success': False,
                'message': f'Domain {domain} not found'
            }

        # Get domain details
        result = db_manager.get_domains(domain_name=domain, limit=1)

        if not result['domains']:
            return {
                'success': False,
                'message': f'Could not retrieve details for {domain}'
            }

        domain_info = result['domains'][0]

        # Get subdomain history
        history = db_manager.get_subdomain_history(domain, limit=10)

        # Get recent scans
        # Note: This would require additional database query
        # For now, we'll use the scan_count from domain info

        return {
            'success': True,
            'domain': domain_info,
            'subdomain_count': history['total_count'],
            'recent_subdomains': history['history'][:5]  # Top 5 recent
        }

    finally:
        db_manager.close()
