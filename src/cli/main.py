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

from src.cli.commands_scan import batch_scan_subfinder_command
from src.cli.commands_results import (
    view_scans_command, results_command
)
from src.cli.commands_domain import (
    domain_add_command, domain_list_command, domain_update_command,
    domain_remove_command
)
from src.cli.commands_analysis import (
    run_analysis_command, list_findings_command, show_finding_command,
    findings_statistics_command, update_finding_status_command
)
from src.cli.formatters import format_output
from src.data.database.sqlmodel_manager import SQLModelManager


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
        openeasd scans                      # List all scan sessions
        openeasd results <scan-id>          # View scan results
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # If no command is provided, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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
@click.option('--contact',
              help='Contact email for this domain')
@click.option('--frequency',
              type=click.Choice(['hourly', 'daily', 'weekly', 'monthly']),
              help='Scan frequency preference')
def domain_add(domain, primary, contact, frequency):
    """Add an apex domain

    Examples:
        openeasd domain add example.com --primary
        openeasd domain add example.io --contact admin@example.io --frequency daily
    """
    try:
        result = domain_add_command(domain, primary, contact, frequency)
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
@click.option('--primary', is_flag=True,
              help='Show only primary domains')
@click.option('--details', is_flag=True,
              help='Show detailed information for each domain')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def domain_list(limit, primary, details, output):
    """List all domains

    Examples:
        openeasd domain list
        openeasd domain list --primary
        openeasd domain list --details
        openeasd domain list --output json
    """
    try:
        result = domain_list_command(limit, primary, details, output)
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
def domain_update(domain, primary):
    """Update domain metadata

    Examples:
        openeasd domain update example.com --primary true
        openeasd domain update example.com --primary false
    """
    try:
        result = domain_update_command(domain, primary)
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
        result = domain_remove_command(domain, force)
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


@cli.group()
def analysis():
    """Manage security findings and analysis results

    View, manage, and analyze security findings from completed scans.

    Examples:
        openeasd analysis findings              # List all findings
        openeasd analysis findings --severity high  # Filter by severity
        openeasd analysis show <finding-id>     # Show finding details
        openeasd analysis stats                 # Show statistics
    """
    pass


@analysis.command('run')
@click.argument('scan_id')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def analysis_run(scan_id, output):
    """Run analysis on a completed scan

    Executes vulnerability detection detectors on scan results.

    Examples:
        openeasd analysis run <scan-id>
    """
    try:
        run_analysis_command(scan_id, output)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@analysis.command('findings')
@click.option('--scan-id', help='Filter by scan ID')
@click.option('--asset', help='Filter by affected asset (domain/subdomain/IP)')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              help='Filter by minimum severity')
@click.option('--limit', default=50, type=int,
              help='Maximum findings to show (default: 50)')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def analysis_findings(scan_id, asset, severity, limit, output):
    """List security findings with optional filters

    Examples:
        openeasd analysis findings
        openeasd analysis findings --severity high
        openeasd analysis findings --scan-id <scan-id>
        openeasd analysis findings --asset example.com --output json
    """
    try:
        result = list_findings_command(scan_id=scan_id, asset=asset, min_severity=severity,
                                       limit=limit, output_format=output)
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@analysis.command('show')
@click.argument('finding_id')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def analysis_show(finding_id, output):
    """Show detailed information for a finding

    Examples:
        openeasd analysis show <finding-id>
        openeasd analysis show <finding-id> --output json
    """
    try:
        show_finding_command(finding_id, output)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@analysis.command('stats')
@click.option('--scan-id', help='Filter by scan ID')
@click.option('--asset', help='Filter by affected asset')
@click.option('--output', type=click.Choice(['table', 'json']),
              default='table',
              help='Output format (default: table)')
def analysis_stats(scan_id, asset, output):
    """Show finding statistics

    Examples:
        openeasd analysis stats
        openeasd analysis stats --scan-id <scan-id>
        openeasd analysis stats --asset example.com
    """
    try:
        result = findings_statistics_command(scan_id=scan_id, asset=asset, output_format=output)
        if result:
            click.echo(format_output(result, output))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@analysis.command('update')
@click.argument('finding_id')
@click.argument('status', type=click.Choice(['open', 'acknowledged', 'resolved', 'false_positive']))
@click.option('--notes', help='Optional notes about the status change')
def analysis_update(finding_id, status, notes):
    """Update finding status

    Examples:
        openeasd analysis update <finding-id> resolved
        openeasd analysis update <finding-id> false_positive --notes "Not applicable"
    """
    try:
        result = update_finding_status_command(finding_id, status, notes)
        if result:
            click.echo(result.get('message', 'Finding updated'))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    cli()


if __name__ == '__main__':
    main()
