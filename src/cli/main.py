"""
OpenEASD CLI - Command-line interface for passive subdomain enumeration.

Usage:
    openeasd scan <domain> [options]
    openeasd history [options]
    openeasd results <scan-id> [options]
"""

import click
import sys
import json
from pathlib import Path

from src.cli.commands import (
    scan_command, history_command, results_command, view_scans_command,
    batch_scan_subfinder_command, run_tool_subfinder_command, run_tool_naabu_command,
    run_tool_dnsx_command, run_tool_httpx_command
)
from src.cli.commands_domain import (
    domain_add_command, domain_list_command, domain_update_command,
    domain_remove_command, domain_show_command
)
from src.cli.formatters import format_output
from src.data.database.duckdb_manager import DuckDBManager


@click.group(invoke_without_command=True)
@click.version_option(version='1.0.0', prog_name='openeasd')
@click.pass_context
def cli(ctx):
    """OpenEASD - Automated External Attack Surface Detection

    Complete reconnaissance workflow: subfinder → dnsx → naabu

    Examples:
        openeasd scan                       # Scan all domains
        openeasd domain add example.com     # Add domain to database
        openeasd domain list                # List all domains
        openeasd history                    # Show scan history
        openeasd run subfinder example.com  # Run tool without saving
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # If no command is provided, run history by default
    if ctx.invoked_subcommand is None:
        ctx.invoke(history)


def _run_tool(tool_func, **kwargs):
    """Helper to run a tool and print results."""
    try:
        result = tool_func(kwargs)
        if not result.get('success'):
            click.echo(f"Error: {result.get('error', 'Unknown error')}", err=True)
            sys.exit(1)
        
        # Format and print the output
        output = kwargs.get('output', 'table')
        if output == 'json':
            click.echo(json.dumps(result, indent=2))
        else:
            # The formatters are designed for the main commands, so we'll do some basic printing here
            if 'subdomains' in result:
                click.echo("\n".join(result['subdomains']))
            elif 'ports' in result:
                for port_info in result['ports']:
                    click.echo(f"{port_info['subdomain']}:{port_info['port']}")
            elif 'records' in result:
                 for record in result['records']:
                    click.echo(f"{record['host']}: {record}")
            elif 'probes' in result:
                for probe in result['probes']:
                    click.echo(f"{probe['url']} - {probe['status_code']}")

    except KeyboardInterrupt:
        click.echo("\n\nTool cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--timeout', default=300, type=int,
              help='Scan timeout in seconds per domain (default: 300)')
@click.option('--primary', is_flag=True,
              help='Scan only primary domains')
def scan(timeout, primary):
    """Complete reconnaissance workflow: subfinder → dnsx → naabu

    Scans all domains from database with complete reconnaissance pipeline:
    - Subdomain discovery (subfinder)
    - DNS resolution (dnsx)
    - Port scanning (naabu)

    Usage:
        openeasd scan                    # Scan all domains
        openeasd scan --primary          # Scan only primary domains
        openeasd scan --timeout 600      # Custom timeout per domain

    Note: To scan a specific domain without adding to database, use:
        openeasd run subfinder <domain>
        openeasd run dnsx <domain>
        openeasd run naabu <target>
    """
    try:
        result = batch_scan_subfinder_command(locals())

        if not result.get('success'):
            click.echo(f"Error: {result.get('message', 'Unknown error')}", err=True)
            sys.exit(1)

        # Display summary
        click.echo()
        click.echo("=" * 60)
        click.echo("Batch Scan Summary")
        click.echo("=" * 60)
        click.echo(f"Total domains: {result.get('total_domains', 0)}")
        click.echo(f"Successful scans: {result.get('successful_scans', 0)}")
        click.echo(f"Failed scans: {result.get('failed_scans', 0)}")
        click.echo()

        # Display individual scan results
        if result.get('scans'):
            click.echo("Scan Results:")
            click.echo("-" * 100)
            click.echo(f"{'Status':<8} {'Domain':<40} {'Subdomains':<12} {'Active':<8} {'Ports':<8}")
            click.echo("-" * 100)
            for scan_result in result['scans']:
                if scan_result.get('status') == 'success':
                    status_icon = "✓"
                    color = 'green'
                    subdomains = scan_result.get('subdomains', 0)
                    active = scan_result.get('active_subdomains', 0)
                    ports = scan_result.get('open_ports', 0)
                    line = f"{status_icon:<8} {scan_result['domain']:<40} {subdomains:<12} {active:<8} {ports:<8}"
                    click.secho(line, fg=color)
                else:
                    status_icon = "✗"
                    color = 'red'
                    error = scan_result.get('error', 'Unknown error')[:50]
                    line = f"{status_icon:<8} {scan_result['domain']:<40} Failed: {error}"
                    click.secho(line, fg=color)

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
def scans(limit, output):
    """List all scan IDs"""
    try:
        result = view_scans_command(locals())
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
def history(limit, output):
    """Show scan history"""
    try:
        result = history_command(locals())
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
def results(scan_id, output):
    """Show results for a specific scan"""
    try:
        result = results_command(locals())
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def domain():
    """Manage domains"""
    pass


@domain.command('add')
@click.argument('domain')
@click.option('--primary', is_flag=True,
              help='Mark as primary domain')
@click.option('--notes',
              help='Notes about the domain')
@click.option('--tags',
              help='Comma-separated tags (e.g., "production,critical"')
@click.option('--contact',
              help='Contact email for this domain')
@click.option('--frequency',
              type=click.Choice(['hourly', 'daily', 'weekly', 'monthly']),
              help='Scan frequency preference')
def domain_add(domain, primary, notes, tags, contact, frequency):
    """Add an apex domain

    Examples:
        openeasd domain add example.com --primary
        openeasd domain add example.io --notes "Secondary domain" --tags "staging,test"
    """
    try:
        result = domain_add_command(locals())
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
    """List all domains

    Examples:
        openeasd domain list
        openeasd domain list --primary
        openeasd domain list --type apex --output json
    """
    try:
        result = domain_list_command(locals())
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
def domain_update(domain, primary, notes, tags):
    """Update domain metadata

    Examples:
        openeasd domain update example.com --notes "Updated notes"
        openeasd domain update example.com --primary true
        openeasd domain update example.com --tags "prod,critical"
    """
    try:
        result = domain_update_command(locals())
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
    """Remove a domain

    Examples:
        openeasd domain remove example.com
        openeasd domain remove example.io --force
    """
    try:
        result = domain_remove_command(locals())
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
    try:
        result = domain_show_command(locals())
        if result.get('success'):
            click.echo(format_output(result, output))
        else:
            click.echo(f"Error: {result['message']}", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def run():
    """Run individual security tools

    Execute tools directly without database storage.
    Useful for quick reconnaissance and testing.

    Examples:
        openeasd run subfinder example.com
        openeasd run naabu api.example.com
        openeasd run dnsx example.com --records a --records mx
    """
    pass


@run.command('subfinder')
@click.argument('domains', nargs=-1, required=True)
@click.option('--timeout', default=300, type=int,
              help='Tool timeout in seconds (default: 300)')
@click.option('--output', type=click.Choice(['table', 'json', 'txt']),
              default='table',
              help='Output format (default: table)')
def run_subfinder(domains, timeout, output):
    """Run subfinder on one or more domains."""
    all_subdomains = []
    for domain in domains:
        click.echo(f"[*] Scanning: {domain}")
        result = run_tool_subfinder_command({'domain': domain, 'timeout': timeout})
        if result.get('success') and result.get('subdomain_count', 0) > 0:
            click.secho(f"  ✓ Found {result['subdomain_count']} subdomains", fg='green')
            all_subdomains.extend(result['subdomains'])
        else:
            click.echo(f"  - No subdomains found")
    
    click.echo()
    click.echo(f"{ '=' * 80}")
    click.echo(f"Total Subdomains Discovered: {len(all_subdomains)}")
    click.echo(f"{ '=' * 80}")

    if output == 'json':
        click.echo(json.dumps(sorted(set(all_subdomains)), indent=2))
    elif output == 'txt':
        for subdomain in sorted(set(all_subdomains)):
            click.echo(subdomain)


@run.command('naabu')
@click.argument('targets', nargs=-1, required=True)
@click.option('--top-ports', default=1000, type=int,
              help='Number of top ports to scan (default: 1000)')
@click.option('--timeout', default=300, type=int,
              help='Tool timeout in seconds (default: 300)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def run_naabu(targets, top_ports, timeout, output):
    """Run naabu port scanner."""
    _run_tool(run_tool_naabu_command, targets=list(targets), top_ports=top_ports, timeout=timeout, output=output)


@run.command('dnsx')
@click.argument('domains', nargs=-1, required=True)
@click.option('--records', '-r', 'record_types', multiple=True,
              type=click.Choice(['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'ptr', 'soa', 'srv'], case_sensitive=False),
              help='DNS record types to query (can specify multiple)')
@click.option('--timeout', default=300, type=int,
              help='Tool timeout in seconds (default: 300)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def run_dnsx(domains, record_types, timeout, output):
    """Run dnsx DNS toolkit."""
    _run_tool(run_tool_dnsx_command, domains=list(domains), record_types=list(record_types), timeout=timeout, output=output)


@run.command('httpx')
@click.argument('targets', nargs=-1, required=True)
@click.option('--threads', default=50, type=int,
              help='Number of concurrent threads (default: 50)')
@click.option('--timeout', default=300, type=int,
              help='Tool timeout in seconds (default: 300)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def run_httpx(targets, threads, timeout, output):
    """Run httpx HTTP probe."""
    _run_tool(run_tool_httpx_command, targets=list(targets), threads=threads, timeout=timeout, output=output)


def main():
    """Main CLI entry point."""
    cli()


if __name__ == '__main__':
    main()