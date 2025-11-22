"""
OpenEASD CLI - Command-line interface for passive subdomain enumeration.

Usage:
    openeasd scan <domain> [options]
    openeasd history [options]
    openeasd results <scan-id> [options]
"""

import click
import sys
from pathlib import Path

from src.cli.commands import scan_command, history_command, results_command, view_scans_command, batch_scan_subfinder_command
from src.cli.commands_domain import (
    domain_add_command, domain_list_command, domain_update_command,
    domain_remove_command, domain_show_command
)
from src.cli.formatters import format_output
from src.utils.config import Config


@click.group(invoke_without_command=True)
@click.version_option(version='1.0.0', prog_name='openeasd')
@click.pass_context
def cli(ctx):
    """OpenEASD - Passive Subdomain Enumeration Tool

    Multi-Organization External Attack Surface Detection

    Examples:
        openeasd scan domain example.com --org "Example"
        openeasd scan subfinder          # Scan all domains in org
        openeasd org set "Tesla"         # Set default org
        openeasd history                 # Uses default org
        openeasd scans                   # Uses default org
    """
    # Load config
    config = Config()

    # Store filter_org in context for all subcommands
    ctx.ensure_object(dict)

    # Use default organization from config
    default_org = config.get_default_organization()
    ctx.obj['filter_org'] = default_org

    # If no command is provided, run history by default
    if ctx.invoked_subcommand is None:
        ctx.invoke(history)


@cli.group()
def scan():
    """Passive subdomain enumeration

    Usage:
        openeasd scan domain <domain>        # Scan a single domain
        openeasd scan subfinder               # Scan all domains in org
    """
    pass


@scan.command('domain')
@click.argument('domain')
@click.option('--org', '--organization', 'organization',
              help='Organization name (e.g., Tesla, Google)')
@click.option('--timeout', default=300, type=int,
              help='Scan timeout in seconds (default: 300)')
@click.option('--output', type=click.Choice(['table', 'json', 'csv', 'txt']),
              default='table',
              help='Output format (default: table)')
@click.option('--no-save', is_flag=True,
              help='Do not save results to database')
def scan_domain(domain, organization, timeout, output, no_save):
    """Scan a single domain"""

    # Create args object compatible with existing command functions
    class Args:
        pass

    args = Args()
    args.domain = domain
    args.organization = organization
    args.timeout = timeout
    args.output = output
    args.save = not no_save  # Save by default, unless --no-save is used

    try:
        result = scan_command(args)
        if result:
            click.echo(format_output(result, output))
    except KeyboardInterrupt:
        click.echo("\n\nScan cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@scan.command('subfinder')
@click.option('--timeout', default=300, type=int,
              help='Scan timeout in seconds per domain (default: 300)')
@click.option('--primary', is_flag=True,
              help='Scan only primary domains')
def scan_subfinder(timeout, primary):
    """Scan all domains in the default organization using subfinder

    This command will scan all domains that have been added to your default
    organization. Use --primary to scan only primary domains.

    Examples:
        openeasd scan subfinder                    # Scan all domains
        openeasd scan subfinder --primary          # Scan only primary domains
        openeasd scan subfinder --timeout 600      # Set timeout per domain
    """

    # Create args object compatible with existing command functions
    class Args:
        pass

    args = Args()
    args.timeout = timeout
    args.primary = primary

    try:
        result = batch_scan_subfinder_command(args)

        if not result.get('success'):
            click.echo(f"Error: {result.get('message', 'Unknown error')}", err=True)
            sys.exit(1)

        # Display summary
        click.echo()
        click.echo("=" * 60)
        click.echo("Batch Scan Summary")
        click.echo("=" * 60)
        click.echo(f"Organization: {result.get('organization', 'Unknown')}")
        click.echo(f"Total domains: {result.get('total_domains', 0)}")
        click.echo(f"Successful scans: {result.get('successful_scans', 0)}")
        click.echo(f"Failed scans: {result.get('failed_scans', 0)}")
        click.echo()

        # Display individual scan results
        if result.get('scans'):
            click.echo("Scan Results:")
            click.echo("-" * 60)
            for scan in result['scans']:
                if scan.get('status') == 'success':
                    click.secho(f"✓ {scan['domain']:<40} {scan['subdomains']} subdomains", fg='green')
                else:
                    click.secho(f"✗ {scan['domain']:<40} Failed: {scan.get('error', 'Unknown error')}", fg='red')

            click.echo()
        elif result.get('message'):
            click.echo(result.get('message'))

    except KeyboardInterrupt:
        click.echo("\n\nBatch scan cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--limit', default=20, type=int,
              help='Number of scans to show (default: 20)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
@click.pass_context
def scans(ctx, limit, output):
    """List all scan IDs"""

    # Create args object compatible with existing command functions
    class Args:
        pass

    args = Args()
    args.limit = limit
    args.output = output
    args.filter_org = ctx.obj.get('filter_org')  # Get global org filter

    try:
        result = view_scans_command(args)
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--limit', default=10, type=int,
              help='Number of scans to show (default: 10)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
@click.pass_context
def history(ctx, limit, output):
    """Show scan history"""

    # Create args object compatible with existing command functions
    class Args:
        pass

    args = Args()
    args.limit = limit
    args.output = output
    args.filter_org = ctx.obj.get('filter_org')  # Get global org filter

    try:
        result = history_command(args)
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('scan_id')
@click.option('--output', type=click.Choice(['table', 'json', 'csv', 'txt']),
              default='table',
              help='Output format (default: table)')
@click.pass_context
def results(ctx, scan_id, output):
    """Show results for a specific scan"""

    # Create args object compatible with existing command functions
    class Args:
        pass

    args = Args()
    args.scan_id = scan_id
    args.output = output
    args.filter_org = ctx.obj.get('filter_org')  # Get global org filter

    try:
        result = results_command(args)
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def domain():
    """Manage domains for current organization"""
    pass


@domain.command('add')
@click.argument('domain')
@click.option('--primary', is_flag=True,
              help='Mark as primary domain')
@click.option('--notes',
              help='Notes about the domain')
@click.option('--tags',
              help='Comma-separated tags (e.g., "production,critical")')
@click.option('--contact',
              help='Contact email for this domain')
@click.option('--frequency',
              type=click.Choice(['hourly', 'daily', 'weekly', 'monthly']),
              help='Scan frequency preference')
def domain_add(domain, primary, notes, tags, contact, frequency):
    """Add an apex domain to current organization

    Examples:
        openeasd domain add example.com --primary
        openeasd domain add example.io --notes "Secondary domain" --tags "staging,test"
    """
    class Args:
        pass

    args = Args()
    args.domain = domain
    args.primary = primary
    args.notes = notes
    args.tags = tags
    args.contact = contact
    args.frequency = frequency

    try:
        result = domain_add_command(args)
        if result.get('success'):
            click.echo(result['message'])
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@domain.command('list')
@click.option('--limit', default=20, type=int,
              help='Number of domains to show (default: 20)')
@click.option('--type', 'domain_type',
              type=click.Choice(['apex', 'subdomain']),
              help='Filter by domain type')
@click.option('--primary', is_flag=True,
              help='Show only primary domains')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def domain_list(limit, domain_type, primary, output):
    """List all domains in current organization

    Examples:
        openeasd domain list
        openeasd domain list --primary
        openeasd domain list --type apex --output json
    """
    class Args:
        pass

    args = Args()
    args.limit = limit
    args.type = domain_type
    args.primary = primary
    args.output = output

    try:
        result = domain_list_command(args)
        if result.get('success'):
            if result.get('domains'):
                click.echo(format_output(result, output))
            else:
                click.echo(result.get('message', 'No domains found'))
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@domain.command('update')
@click.argument('domain')
@click.option('--primary', type=bool,
              help='Set primary status (true/false)')
@click.option('--notes',
              help='Update notes')
@click.option('--tags',
              help='Update tags (comma-separated)')
@click.option('--contact',
              help='Update contact email')
@click.option('--frequency',
              type=click.Choice(['hourly', 'daily', 'weekly', 'monthly']),
              help='Update scan frequency')
@click.option('--active-scan', type=bool,
              help='Enable/disable active scanning (true/false)')
def domain_update(domain, primary, notes, tags, contact, frequency, active_scan):
    """Update domain metadata

    Examples:
        openeasd domain update example.com --notes "Updated notes"
        openeasd domain update example.com --primary true
        openeasd domain update example.com --tags "prod,critical" --frequency daily
    """
    class Args:
        pass

    args = Args()
    args.domain = domain
    args.primary = primary
    args.notes = notes
    args.tags = tags
    args.contact = contact
    args.frequency = frequency
    args.active_scan = active_scan

    try:
        result = domain_update_command(args)
        if result.get('success'):
            click.echo(result['message'])
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@domain.command('remove')
@click.argument('domain')
@click.option('--force', is_flag=True,
              help='Skip confirmation prompt')
def domain_remove(domain, force):
    """Remove a domain from current organization

    Examples:
        openeasd domain remove example.com
        openeasd domain remove example.io --force
    """
    class Args:
        pass

    args = Args()
    args.domain = domain
    args.force = force

    try:
        result = domain_remove_command(args)
        if result.get('success'):
            click.echo()
            click.echo(result['message'])

            # Show detailed deletion counts if available
            if result.get('deleted'):
                deleted = result['deleted']
                click.echo()
                click.echo("Deleted records:")
                click.echo(f"  Scan Sessions:        {deleted.get('scan_sessions', 0):>6}")
                click.echo(f"  Security Alerts:      {deleted.get('security_alerts', 0):>6}")
                click.echo(f"  Subfinder Results:    {deleted.get('subfinder_results', 0):>6}")
                click.echo(f"  Amass Results:        {deleted.get('amass_results', 0):>6}")
                click.echo(f"  Nmap Results:         {deleted.get('nmap_results', 0):>6}")
                click.echo(f"  Naabu Results:        {deleted.get('naabu_results', 0):>6}")
                click.echo(f"  Tool History:         {deleted.get('subfinder_history', 0) + deleted.get('amass_history', 0) + deleted.get('nmap_history', 0) + deleted.get('naabu_history', 0) + deleted.get('subdomain_history', 0):>6}")
                click.echo(f"{'-' * 40}")
                click.echo(f"  TOTAL:                {deleted.get('total_records_deleted', 0):>6} records")
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n\nRemoval cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@domain.command('show')
@click.argument('domain')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def domain_show(domain, output):
    """Show detailed information about a domain

    Examples:
        openeasd domain show example.com
        openeasd domain show example.com --output json
    """
    class Args:
        pass

    args = Args()
    args.domain = domain
    args.output = output

    try:
        result = domain_show_command(args)
        if result.get('success'):
            click.echo(format_output(result, output))
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def org():
    """Manage OpenEASD Org"""
    pass


@org.command('set')
@click.argument('organization')
def set_org(organization):
    """Set default organization

    Examples:
        openeasd org set "Tesla"
        openeasd org set "amnic"
    """
    cfg = Config()
    cfg.set_default_organization(organization)
    click.echo(f"✓ Default organization set to: {organization}")
    click.echo(f"\nNow all commands will filter by '{organization}' unless --org is specified.")


@org.command('clear')
def clear_org():
    """Clear default organization

    Example:
        openeasd org clear
    """
    cfg = Config()
    cfg.clear_default_organization()
    click.echo("✓ Default organization cleared")
    click.echo("\nAll commands will now show data from all organizations.")


@org.command('show')
def show_config():
    """Show current configuration

    Example:
        openeasd org show
    """
    import asyncio
    from src.data.database.organization_manager import OrganizationManager

    cfg = Config()
    default_org = cfg.get_default_organization()

    click.echo("=" * 80)
    click.echo("OpenEASD Configuration")
    click.echo("=" * 80)

    # Show default org
    if default_org:
        click.echo(f"Default Organization: {default_org}")
    else:
        click.echo("Default Organization: (not set)")

    click.echo(f"Config File: {cfg.config_path}")
    click.echo()

    # Show available organizations
    click.echo("Available Organizations:")
    click.echo("-" * 80)

    async def _list_orgs():
        org_manager = OrganizationManager()
        await org_manager.initialize()
        try:
            orgs = await org_manager.list_organizations()
            return orgs
        finally:
            await org_manager.close()

    try:
        orgs = asyncio.run(_list_orgs())
        if orgs:
            # Table header
            click.echo(f"{'Organization':<30} {'Domains':<10} {'Scans':<10} {'Last Scan':<20}")
            click.echo("-" * 80)

            for org in orgs:
                org_name = org['org_name']
                total_domains = org.get('total_domains', 0)
                total_scans = org.get('total_scans', 0)
                last_scan = org.get('last_scan_at')
                last_scan_str = last_scan.strftime('%Y-%m-%d %H:%M:%S') if last_scan else 'Never'

                # Highlight default org
                if default_org and org_name == default_org:
                    click.secho(f"{org_name:<30} {total_domains:<10} {total_scans:<10} {last_scan_str:<20} (DEFAULT)", fg='green')
                else:
                    click.echo(f"{org_name:<30} {total_domains:<10} {total_scans:<10} {last_scan_str:<20}")
        else:
            click.echo("  No organizations found. Run a scan to create one.")
    except Exception as e:
        click.echo(f"  Error listing organizations: {e}", err=True)

    click.echo("=" * 80)
    click.echo()
    click.echo("To set default: openeasd org set <organization>")


@org.command('list')
def list_orgs():
    """List all available organizations

    Example:
        openeasd org list
    """
    import asyncio
    from src.data.database.organization_manager import OrganizationManager

    cfg = Config()
    default_org = cfg.get_default_organization()

    async def _list_orgs():
        org_manager = OrganizationManager()
        await org_manager.initialize()
        try:
            orgs = await org_manager.list_organizations()
            return orgs
        finally:
            await org_manager.close()

    try:
        orgs = asyncio.run(_list_orgs())

        if not orgs:
            click.echo("No organizations found. Run a scan to create one.")
            return

        click.echo("=" * 80)
        click.echo("Available Organizations")
        click.echo("=" * 80)
        click.echo()
        click.echo(f"{'Organization':<30} {'Domains':<10} {'Scans':<10} {'Last Scan':<20}")
        click.echo("-" * 80)

        for org in orgs:
            org_name = org['org_name']
            total_domains = org.get('total_domains', 0)
            total_scans = org.get('total_scans', 0)
            last_scan = org.get('last_scan_at')
            last_scan_str = last_scan.strftime('%Y-%m-%d %H:%M:%S') if last_scan else 'Never'

            # Highlight default org
            if default_org and org_name == default_org:
                click.secho(f"{org_name:<30} {total_domains:<10} {total_scans:<10} {last_scan_str:<20} ★ DEFAULT", fg='green')
            else:
                click.echo(f"{org_name:<30} {total_domains:<10} {total_scans:<10} {last_scan_str:<20}")

        click.echo("=" * 80)
        click.echo()
        if default_org:
            click.echo(f"Current default: {default_org}")
        else:
            click.echo("No default organization set")
        click.echo()
        click.echo("Use: openeasd org set <organization>")

    except Exception as e:
        click.echo(f"Error listing organizations: {e}", err=True)
        sys.exit(1)


@org.command('create')
@click.argument('organization')
@click.option('--contact-email',
              help='Contact email for the organization')
@click.option('--contact-name',
              help='Contact name for the organization')
@click.option('--industry',
              help='Industry sector (e.g., "Technology", "Finance")')
@click.option('--tags',
              help='Comma-separated tags (e.g., "client,important")')
@click.option('--notes',
              help='Notes about the organization')
@click.option('--set-default', is_flag=True,
              help='Set as default organization after creation')
def create_org(organization, contact_email, contact_name, industry, tags, notes, set_default):
    """Create a new organization

    Creates a new organization with dedicated database and optional metadata.

    Examples:
        openeasd org create "Tesla"
        openeasd org create "Acme Corp" --set-default
        openeasd org create "Example Inc" --contact-email "admin@example.com" --industry "Technology"
        openeasd org create "Client XYZ" --tags "client,vip" --notes "Important client"
    """
    import asyncio
    from src.data.database.organization_manager import OrganizationManager

    async def _create_org():
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Build metadata dictionary
            metadata = {}
            if contact_email:
                metadata['contact_email'] = contact_email
            if contact_name:
                metadata['contact_name'] = contact_name
            if industry:
                metadata['industry'] = industry
            if tags:
                # Convert comma-separated string to list
                metadata['tags'] = [tag.strip() for tag in tags.split(',')]
            if notes:
                metadata['notes'] = notes

            # Create organization
            result = await org_manager.create_organization(
                organization,
                metadata=metadata if metadata else None
            )

            if result['created']:
                click.echo()
                click.secho(f"✓ Organization created: {result['org_name']}", fg='green')
                click.echo(f"  Organization ID: {result['org_id']}")
                click.echo(f"  Slug: {result['org_slug']}")
                click.echo(f"  Database: {result['db_path']}")

                if metadata:
                    click.echo()
                    click.echo("Metadata:")
                    if contact_email:
                        click.echo(f"  Contact Email: {contact_email}")
                    if contact_name:
                        click.echo(f"  Contact Name: {contact_name}")
                    if industry:
                        click.echo(f"  Industry: {industry}")
                    if tags:
                        click.echo(f"  Tags: {tags}")
                    if notes:
                        click.echo(f"  Notes: {notes}")

                # Set as default if requested
                if set_default:
                    cfg = Config()
                    cfg.set_default_organization(organization)
                    click.echo()
                    click.secho(f"✓ Set as default organization", fg='green')

                click.echo()
                return True
            else:
                click.echo()
                click.echo(f"Organization already exists: {result['org_name']}")
                click.echo(f"  Database: {result['db_path']}")
                click.echo()
                return False

        finally:
            await org_manager.close()

    try:
        success = asyncio.run(_create_org())
        if not success:
            sys.exit(1)
    except Exception as e:
        click.echo()
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@org.command('delete')
@click.argument('organization')
@click.option('--force', is_flag=True,
              help='Skip confirmation prompt')
def delete_org(organization, force):
    """Delete an organization and all its data

    WARNING: This will permanently delete:
      - Organization database
      - All domains
      - All scan sessions
      - All security alerts

    Examples:
        openeasd org delete "Example"
        openeasd org delete "Tesla" --force
    """
    import asyncio
    from src.data.database.organization_manager import OrganizationManager
    from src.data.database.duckdb_manager import DuckDBManager

    async def _delete_org():
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Check if organization exists
            org_info = await org_manager.get_organization_info(organization)

            if not org_info:
                click.echo(f"Error: Organization not found: {organization}", err=True)
                return False

            # Get preview from org database
            db_manager = DuckDBManager(org_info['org_name'], org_info['db_path'])
            await db_manager.initialize()

            try:
                # Count data in org database
                def _count_org_data():
                    domains = db_manager.connection.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
                    alerts = db_manager.connection.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
                    scans = db_manager.connection.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
                    return {'domains': domains, 'alerts': alerts, 'scans': scans}

                counts = await asyncio.get_event_loop().run_in_executor(None, _count_org_data)

                click.echo()
                click.echo("=" * 80)
                click.echo(f"Preview of deletion for organization: {organization}")
                click.echo("=" * 80)
                click.echo()
                click.echo("This will permanently delete:")
                click.echo(f"  - {counts['domains']} domain(s)")
                click.echo(f"  - {counts['alerts']} security alert(s)")
                click.echo(f"  - {counts['scans']} scan session(s)")
                click.echo(f"  - Organization database: {org_info['db_path']}")
                click.echo()

            finally:
                await db_manager.close()

            # Confirm deletion
            if not force:
                click.echo("=" * 80)
                confirmation = click.prompt(
                    "Are you sure you want to delete? This cannot be undone. [y/N]",
                    type=str,
                    default="N"
                )

                if confirmation.strip().lower() != 'y':
                    click.echo()
                    click.echo("Deletion cancelled by user")
                    return False

            # Delete organization
            click.echo()
            click.echo("Deleting...")
            result = await org_manager.delete_organization(organization, force=True)

            if result['success']:
                click.echo()
                click.secho(f"✓ Deleted organization: {organization}", fg='green')
                click.secho(f"✓ Deleted database: {result['db_path']}", fg='green')
                click.echo()

                # Clear default org if it was the deleted one
                cfg = Config()
                default_org = cfg.get_default_organization()
                if default_org and default_org.lower() == organization.lower():
                    cfg.clear_default_organization()
                    click.echo("✓ Cleared default organization (deleted organization was set as default)")
                    click.echo()

                return True
            else:
                click.echo()
                click.echo(f"Error: {result['message']}", err=True)
                return False

        finally:
            await org_manager.close()

    try:
        success = asyncio.run(_delete_org())
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        click.echo()
        click.echo()
        click.echo("Deletion cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo()
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    cli()


if __name__ == '__main__':
    main()
