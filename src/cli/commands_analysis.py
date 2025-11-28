"""
Analysis CLI commands for OpenEASD.

Commands for managing and viewing security findings from the Analysis Layer.
"""

import asyncio
import click
from typing import Optional
from src.data.database.sqlmodel_manager import SQLModelManager
from src.analysis.analysis_service import AnalysisService
from src.cli.formatters import format_table, format_json


def run_analysis_command(scan_id: str, output_format: str = 'table'):
    """
    Run analysis manually on a completed scan.

    Args:
        scan_id: Scan session UUID
        output_format: Output format (table/json)
    """
    db = SQLModelManager()
    db.initialize()

    try:
        # Get scan data
        scan = db.get_scan_status(scan_id)
        if not scan:
            click.echo(f"❌ Scan {scan_id} not found", err=True)
            return

        if scan['status'] != 'completed':
            click.echo(f"⚠️  Scan {scan_id} is not completed (status: {scan['status']})", err=True)
            return

        # Get scan results
        subfinder_results = db.get_tool_results(scan_id, tool_name='subfinder')
        naabu_results = db.get_tool_results(scan_id, tool_name='naabu')

        # Prepare scan data
        scan_data = {
            'scan_id': scan_id,
            'subfinder_results': subfinder_results.get('results', []),
            'naabu_results': naabu_results.get('results', [])
        }

        # Initialize analysis service
        analysis_service = AnalysisService(db_manager=db)

        if not analysis_service.is_enabled():
            click.echo("❌ Analysis Layer is disabled in configuration", err=True)
            return

        click.echo(f"🔍 Running analysis on scan {scan_id}...")

        # Run analysis
        results = asyncio.run(
            analysis_service.analyze_scan_results(scan_id, scan_data)
        )

        # Display results
        if output_format == 'json':
            click.echo(format_json(results))
        else:
            click.echo(f"\n✅ Analysis completed!")
            click.echo(f"📊 Findings: {results['findings_count']}")

            stats = results.get('statistics', {})
            click.echo(f"\n📈 Statistics:")
            click.echo(f"  Critical: {stats.get('critical_findings', 0)}")
            click.echo(f"  High:     {stats.get('high_findings', 0)}")
            click.echo(f"  Medium:   {stats.get('medium_findings', 0)}")
            click.echo(f"  Low:      {stats.get('low_findings', 0)}")
            click.echo(f"  Info:     {stats.get('info_findings', 0)}")

            if results['findings_count'] > 0:
                click.echo(f"\n💡 Use 'openeasd findings --scan-id {scan_id}' to view details")

    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}", err=True)
        raise
    finally:
        db.close()


def list_findings_command(
    scan_id: Optional[str] = None,
    asset: Optional[str] = None,
    min_severity: Optional[str] = None,
    limit: int = 50,
    output_format: str = 'table'
):
    """
    List security findings with optional filters.

    Args:
        scan_id: Filter by scan ID
        asset: Filter by affected asset
        min_severity: Minimum severity (critical/high/medium/low/info)
        limit: Maximum number of findings to display
        output_format: Output format (table/json)
    """
    db = SQLModelManager()
    db.initialize()

    try:
        # Get findings
        result = db.get_findings(
            scan_id=scan_id,
            affected_asset=asset,
            min_severity=min_severity,
            limit=limit
        )

        findings = result.get('findings', [])
        total_count = result.get('total_count', 0)

        if not findings:
            click.echo("ℹ️  No findings found")
            return

        if output_format == 'json':
            click.echo(format_json(result))
        else:
            # Display summary
            click.echo(f"\n🔍 Security Findings ({len(findings)}/{total_count})")

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
                # Truncate ID for display
                finding_id = finding['id'][:8] + '...'

                # Severity with color emoji
                severity = finding['severity']
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢',
                    'info': '🔵'
                }.get(severity, '⚪')

                risk_score = finding['risk_score']
                finding_type = finding['finding_type']
                affected_asset = finding['affected_asset']

                # Truncate title
                title = finding['title']
                if len(title) > 50:
                    title = title[:47] + '...'

                status = finding['status']

                rows.append([
                    finding_id,
                    f"{severity_icon} {severity}",
                    risk_score,
                    finding_type,
                    affected_asset,
                    title,
                    status
                ])

            # Display table
            from texttable import Texttable
            table = Texttable()
            table.set_cols_width([12, 20, 6, 20, 20, 30, 10])
            table.add_rows([headers] + rows)
            click.echo(table.draw())

            if result.get('has_more', False):
                click.echo(f"\n💡 {total_count - len(findings)} more findings available. Use --limit to see more.")

    except Exception as e:
        click.echo(f"❌ Failed to retrieve findings: {e}", err=True)
        raise
    finally:
        db.close()


def show_finding_command(finding_id: str, output_format: str = 'table'):
    """
    Show detailed information about a specific finding.

    Args:
        finding_id: Finding UUID
        output_format: Output format (table/json)
    """
    db = SQLModelManager()
    db.initialize()

    try:
        finding = db.get_finding_by_id(finding_id)

        if not finding:
            click.echo(f"❌ Finding {finding_id} not found", err=True)
            return

        if output_format == 'json':
            click.echo(format_json(finding))
        else:
            # Display finding details
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢',
                'info': '🔵'
            }.get(finding['severity'], '⚪')

            click.echo(f"\n{severity_icon} Security Finding Details")
            click.echo("=" * 80)

            click.echo(f"\n📋 Basic Information:")
            click.echo(f"  ID:               {finding['id']}")
            click.echo(f"  Scan ID:          {finding['scan_id']}")
            click.echo(f"  Finding Type:     {finding['finding_type']}")
            click.echo(f"  Affected Asset:   {finding['affected_asset']}")

            if finding.get('port'):
                click.echo(f"  Port:             {finding['port']}/{finding.get('protocol', 'tcp')}")
            if finding.get('service_name'):
                click.echo(f"  Service:          {finding['service_name']}")

            click.echo(f"\n📊 Risk Assessment:")
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

            click.echo(f"\n📝 Details:")
            click.echo(f"  Title:            {finding['title']}")
            if finding.get('description'):
                click.echo(f"  Description:      {finding['description']}")

            if finding.get('remediation'):
                click.echo(f"\n🔧 Remediation:")
                click.echo(f"  {finding['remediation']}")

            click.echo(f"\n📌 Status:")
            click.echo(f"  Status:           {finding['status']}")
            click.echo(f"  False Positive:   {finding.get('false_positive', False)}")

            if finding.get('resolved_at'):
                click.echo(f"  Resolved At:      {finding['resolved_at']}")
            if finding.get('resolution_notes'):
                click.echo(f"  Resolution Notes: {finding['resolution_notes']}")

            click.echo(f"\n⏰ Timestamps:")
            click.echo(f"  Discovered:       {finding['discovered_at']}")
            click.echo(f"  Last Updated:     {finding['updated_at']}")

            if finding.get('detector'):
                click.echo(f"\n🔍 Detected by:     {finding['detector']}")

    except Exception as e:
        click.echo(f"❌ Failed to retrieve finding: {e}", err=True)
        raise
    finally:
        db.close()


def findings_statistics_command(
    scan_id: Optional[str] = None,
    asset: Optional[str] = None,
    output_format: str = 'table'
):
    """
    Show findings statistics.

    Args:
        scan_id: Filter by scan ID
        asset: Filter by affected asset
        output_format: Output format (table/json)
    """
    db = SQLModelManager()
    db.initialize()

    try:
        stats = db.get_findings_statistics(
            scan_id=scan_id,
            affected_asset=asset
        )

        if output_format == 'json':
            click.echo(format_json(stats))
        else:
            click.echo(f"\n📊 Findings Statistics")
            click.echo("=" * 50)

            if scan_id:
                click.echo(f"Scan ID: {scan_id}")
            if asset:
                click.echo(f"Asset: {asset}")

            click.echo(f"\n📈 Overview:")
            click.echo(f"  Total Findings:      {stats['total_findings']}")
            click.echo(f"  Average Risk Score:  {stats['average_risk_score']}/100")

            click.echo(f"\n🎯 By Severity:")
            click.echo(f"  🔴 Critical:         {stats['critical_findings']}")
            click.echo(f"  🟠 High:             {stats['high_findings']}")
            click.echo(f"  🟡 Medium:           {stats['medium_findings']}")
            click.echo(f"  🟢 Low:              {stats['low_findings']}")
            click.echo(f"  🔵 Info:             {stats['info_findings']}")

            click.echo(f"\n📌 By Status:")
            click.echo(f"  Open:                {stats['open_findings']}")
            click.echo(f"  Resolved:            {stats['resolved_findings']}")
            click.echo(f"  False Positives:     {stats['false_positives']}")

    except Exception as e:
        click.echo(f"❌ Failed to retrieve statistics: {e}", err=True)
        raise
    finally:
        db.close()


def update_finding_status_command(
    finding_id: str,
    status: str,
    notes: Optional[str] = None
):
    """
    Update the status of a finding.

    Args:
        finding_id: Finding UUID
        status: New status (open/acknowledged/resolved/false_positive)
        notes: Optional resolution notes
    """
    valid_statuses = ['open', 'acknowledged', 'resolved', 'false_positive']

    if status not in valid_statuses:
        click.echo(f"❌ Invalid status. Must be one of: {', '.join(valid_statuses)}", err=True)
        return

    db = SQLModelManager()
    db.initialize()

    try:
        success = db.update_finding_status(
            finding_id=finding_id,
            status=status,
            resolution_notes=notes
        )

        if not success:
            click.echo(f"❌ Finding {finding_id} not found", err=True)
            return

        click.echo(f"✅ Finding {finding_id} status updated to '{status}'")
        if notes:
            click.echo(f"📝 Resolution notes: {notes}")

    except Exception as e:
        click.echo(f"❌ Failed to update finding status: {e}", err=True)
        raise
    finally:
        db.close()
