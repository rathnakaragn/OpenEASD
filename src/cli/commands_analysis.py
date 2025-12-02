"""
Analysis CLI commands for OpenEASD.

Commands for managing and viewing security findings from the Analysis Layer.
"""

import click
from typing import Optional, Dict, Any
from src.cli.context import CLIContext, cli_command
from src.analysis.analysis_service import AnalysisService
from src.cli.formatters import format_table, format_json


@cli_command
def run_analysis_command(ctx: CLIContext, scan_id: str, output_format: str = 'table') -> Dict[str, Any]:
    """
    Run analysis manually on a completed scan.

    Args:
        ctx: CLI context with services
        scan_id: Scan session UUID
        output_format: Output format (table/json)
    """
    # Get scan data
    scan = ctx.db.get_scan_status(scan_id)
    if not scan:
        click.echo(f"Scan {scan_id} not found", err=True)
        return {'success': False}

    if scan['status'] != 'completed':
        click.echo(f"Scan {scan_id} is not completed (status: {scan['status']})", err=True)
        return {'success': False}

    # Get scan results
    subfinder_results = ctx.db.get_tool_results(scan_id, tool_name='subfinder')
    naabu_results = ctx.db.get_tool_results(scan_id, tool_name='naabu')

    # Prepare scan data
    scan_data = {
        'scan_id': scan_id,
        'subfinder_results': subfinder_results.get('results', []),
        'naabu_results': naabu_results.get('results', [])
    }

    # Initialize analysis service
    analysis_service = AnalysisService(db_manager=ctx.db)

    if not analysis_service.is_enabled():
        click.echo("Analysis Layer is disabled in configuration", err=True)
        return {'success': False}

    click.echo(f"Running analysis on scan {scan_id}...")

    # Run analysis (synchronous call)
    results = analysis_service.analyze_scan_results(scan_id, scan_data)

    # Display results
    if output_format == 'json':
        click.echo(format_json(results))
    else:
        click.echo(f"\nAnalysis completed!")
        click.echo(f"Findings: {results['findings_count']}")

        stats = results.get('statistics', {})
        click.echo(f"\nStatistics:")
        click.echo(f"  Critical: {stats.get('critical_findings', 0)}")
        click.echo(f"  High:     {stats.get('high_findings', 0)}")
        click.echo(f"  Medium:   {stats.get('medium_findings', 0)}")
        click.echo(f"  Low:      {stats.get('low_findings', 0)}")
        click.echo(f"  Info:     {stats.get('info_findings', 0)}")

        if results['findings_count'] > 0:
            click.echo(f"\nUse 'openeasd findings --scan-id {scan_id}' to view details")

    return {'success': True, 'results': results}


@cli_command
def list_findings_command(
    ctx: CLIContext,
    scan_id: Optional[str] = None,
    asset: Optional[str] = None,
    min_severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    output_format: str = 'table'
) -> Dict[str, Any]:
    """
    List security findings with optional filters.

    Args:
        ctx: CLI context with services
        scan_id: Filter by scan ID
        asset: Filter by affected asset
        min_severity: Minimum severity (critical/high/medium/low/info)
        status: Filter by status
        limit: Maximum number of findings to display
        output_format: Output format (table/json)
    """
    # Get findings using service from context
    result = ctx.findings_service.list_findings(
        scan_id=scan_id,
        affected_asset=asset,
        min_severity=min_severity,
        status=status,
        limit=limit
    )

    findings = result.get('findings', [])
    total_count = result.get('total_count', 0)

    if not findings:
        click.echo("No findings found")
        return result

    if output_format == 'json':
        return result

    # Display summary
    click.echo(f"\nSecurity Findings ({len(findings)}/{total_count})")

    if min_severity:
        click.echo(f"   Filtered by: severity >= {min_severity}")
    if scan_id:
        click.echo(f"   Scan ID: {scan_id}")
    if asset:
        click.echo(f"   Asset: {asset}")
    click.echo()

    # Prepare table data
    headers = ['ID', 'Severity', 'Risk', 'Type', 'Asset', 'Title', 'Status']
    rows = []

    for finding in findings:
        finding_id = finding['id'][:8] + '...'
        severity = finding['severity']
        severity_icon = {
            'critical': '[C]', 'high': '[H]', 'medium': '[M]',
            'low': '[L]', 'info': '[I]'
        }.get(severity, '[?]')

        title = finding['title']
        if len(title) > 50:
            title = title[:47] + '...'

        rows.append([
            finding_id,
            f"{severity_icon} {severity}",
            finding['risk_score'],
            finding['finding_type'],
            finding['affected_asset'],
            title,
            finding['status']
        ])

    # Display table
    from texttable import Texttable
    table = Texttable()
    table.set_cols_width([12, 20, 6, 20, 20, 30, 10])
    table.add_rows([headers] + rows)
    click.echo(table.draw())

    if result.get('has_more', False):
        click.echo(f"\n{total_count - len(findings)} more findings available. Use --limit to see more.")

    return result


@cli_command
def show_finding_command(ctx: CLIContext, finding_id: str, output_format: str = 'table') -> Dict[str, Any]:
    """
    Show detailed information about a specific finding.

    Args:
        ctx: CLI context with services
        finding_id: Finding UUID
        output_format: Output format (table/json)
    """
    finding = ctx.findings_service.get_finding(finding_id)

    if output_format == 'json':
        click.echo(format_json(finding))
        return {'success': True, 'finding': finding}

    # Display finding details
    severity_icon = {
        'critical': '[C]',
        'high': '[H]',
        'medium': '[M]',
        'low': '[L]',
        'info': '[I]'
    }.get(finding['severity'], '[?]')

    click.echo(f"\n{severity_icon} Security Finding Details")
    click.echo("=" * 80)

    click.echo(f"\nBasic Information:")
    click.echo(f"  ID:               {finding['id']}")
    click.echo(f"  Scan ID:          {finding['scan_id']}")
    click.echo(f"  Finding Type:     {finding['finding_type']}")
    click.echo(f"  Affected Asset:   {finding['affected_asset']}")

    if finding.get('port'):
        click.echo(f"  Port:             {finding['port']}/{finding.get('protocol', 'tcp')}")
    if finding.get('service_name'):
        click.echo(f"  Service:          {finding['service_name']}")

    click.echo(f"\nRisk Assessment:")
    click.echo(f"  Severity:         {severity_icon} {finding['severity'].upper()}")
    click.echo(f"  Risk Score:       {finding['risk_score']}/100")
    click.echo(f"  Confidence:       {finding.get('confidence_level', 'medium')}")

    if finding.get('cwe_id'):
        click.echo(f"  CWE ID:           {finding['cwe_id']}")

    # Score breakdown
    breakdown = finding.get('score_breakdown', {})
    if breakdown:
        click.echo(f"\n  Score Breakdown:")
        click.echo(f"    Base Score:     {breakdown.get('base_score', 0)}/40")
        click.echo(f"    Context Score:  {breakdown.get('context_score', 0)}/40")
        click.echo(f"    Exposure Score: {breakdown.get('exposure_score', 0)}/20")

    click.echo(f"\nDetails:")
    click.echo(f"  Title:            {finding['title']}")
    if finding.get('description'):
        click.echo(f"  Description:      {finding['description']}")

    if finding.get('remediation'):
        click.echo(f"\nRemediation:")
        click.echo(f"  {finding['remediation']}")

    click.echo(f"\nStatus:")
    click.echo(f"  Status:           {finding['status']}")
    click.echo(f"  False Positive:   {finding.get('false_positive', False)}")

    if finding.get('resolved_at'):
        click.echo(f"  Resolved At:      {finding['resolved_at']}")
    if finding.get('resolution_notes'):
        click.echo(f"  Resolution Notes: {finding['resolution_notes']}")

    click.echo(f"\nTimestamps:")
    click.echo(f"  First Seen:       {finding['first_seen']}")
    click.echo(f"  Last Seen:        {finding['last_seen']}")
    click.echo(f"  Last Updated:     {finding['updated_at']}")
    click.echo(f"  Occurrences:      {finding.get('occurrence_count', 1)}")

    if finding.get('detector'):
        click.echo(f"\nDetected by:     {finding['detector']}")

    return {'success': True, 'finding': finding}


@cli_command
def findings_statistics_command(
    ctx: CLIContext,
    scan_id: Optional[str] = None,
    asset: Optional[str] = None,
    output_format: str = 'table'
) -> Dict[str, Any]:
    """
    Show findings statistics.

    Args:
        ctx: CLI context with services
        scan_id: Filter by scan ID
        asset: Filter by affected asset
        output_format: Output format (table/json)
    """
    stats = ctx.findings_service.get_statistics(
        scan_id=scan_id,
        affected_asset=asset
    )

    if output_format == 'json':
        click.echo(format_json(stats))
        return {'success': True, 'stats': stats}

    click.echo(f"\nFindings Statistics")
    click.echo("=" * 50)

    if scan_id:
        click.echo(f"Scan ID: {scan_id}")
    if asset:
        click.echo(f"Asset: {asset}")

    click.echo(f"\nOverview:")
    click.echo(f"  Total Findings:      {stats['total_findings']}")
    click.echo(f"  Average Risk Score:  {stats['average_risk_score']}/100")

    click.echo(f"\nBy Severity:")
    click.echo(f"  [C] Critical:        {stats['critical_findings']}")
    click.echo(f"  [H] High:            {stats['high_findings']}")
    click.echo(f"  [M] Medium:          {stats['medium_findings']}")
    click.echo(f"  [L] Low:             {stats['low_findings']}")
    click.echo(f"  [I] Info:            {stats['info_findings']}")

    click.echo(f"\nBy Status:")
    click.echo(f"  New:                 {stats.get('new_findings', 0)}")
    click.echo(f"  Open:                {stats['open_findings']}")
    click.echo(f"  Acknowledged:        {stats.get('acknowledged_findings', 0)}")
    click.echo(f"  Resolved:            {stats['resolved_findings']}")
    click.echo(f"  Reopened:            {stats.get('reopened_findings', 0)}")
    click.echo(f"  False Positives:     {stats['false_positives']}")

    click.echo(f"\nSummary:")
    click.echo(f"  Active (needs attention): {stats.get('active_findings', 0)}")
    click.echo(f"  Closed (resolved/FP):     {stats.get('closed_findings', 0)}")

    return {'success': True, 'stats': stats}


@cli_command
def update_finding_status_command(
    ctx: CLIContext,
    finding_id: str,
    status: str,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update the status of a finding.

    Args:
        ctx: CLI context with services
        finding_id: Finding UUID
        status: New status (new/open/acknowledged/resolved/reopened/false_positive)
        notes: Optional resolution notes

    Status lifecycle:
        - new: First time discovered (auto-set on creation)
        - open: Known issue, needs attention
        - acknowledged: Team is aware, working on it
        - resolved: Fixed/closed
        - reopened: Was resolved but detected again (auto-set)
        - false_positive: Not a real issue
    """
    result = ctx.findings_service.update_status(
        finding_id=finding_id,
        status=status,
        resolution_notes=notes
    )

    if result['success']:
        click.echo(f"Finding {finding_id} status updated to '{status}'")
        if notes:
            click.echo(f"Resolution notes: {notes}")
    else:
        click.echo(f"Error: {result['message']}", err=True)

    return result
