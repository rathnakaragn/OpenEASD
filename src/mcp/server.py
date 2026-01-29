"""
OpenEASD MCP Server.

Exposes security scanning tools and resources to AI assistants
via the Model Context Protocol (MCP).

Tools:
    - scan_domain: Start a security scan for a domain
    - get_scan_status: Check the status of a running scan
    - list_scans: List recent scans
    - list_domains: List monitored domains
    - add_domain: Add a new domain to monitor
    - get_findings: Get security findings
    - get_finding_details: Get details of a specific finding
    - update_finding_status: Update finding status (acknowledge, resolve, etc.)

Resources:
    - findings://stats: Current findings statistics
    - domains://list: List of all monitored domains
    - scans://recent: Recent scan activity

Run with:
    fastmcp run src.mcp.server:mcp
"""

import json
import logging
from typing import Optional
from contextlib import contextmanager

from fastmcp import FastMCP

from src.data.database.sqlmodel_manager import SQLModelManager
from src.orchestrator.scan_service import ScanService
from src.orchestrator.domain_service import DomainService
from src.orchestrator.findings_service import FindingsService
from src.orchestrator.exceptions import (
    DomainNotFound,
    DomainAlreadyExists,
    ScanNotFound,
    FindingNotFound,
    InvalidFindingStatus,
)

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP(
    "OpenEASD Security Scanner",
    instructions="External Attack Surface Detection - scan domains for vulnerabilities, "
                 "exposed services, and security issues. Use scan_domain to start scans, "
                 "get_findings to view results, and list_domains to see monitored domains."
)


# =============================================================================
# Database Connection Management
# =============================================================================

@contextmanager
def get_db():
    """Context manager for database connections."""
    db = SQLModelManager()
    db.initialize()
    try:
        yield db
    finally:
        db.close()


def get_services():
    """Get initialized service instances."""
    db = SQLModelManager()
    db.initialize()
    return {
        'db': db,
        'scan': ScanService(db),
        'domain': DomainService(db),
        'findings': FindingsService(db),
    }


# =============================================================================
# Domain Tools
# =============================================================================

@mcp.tool()
def list_domains(
    limit: int = 20,
    primary_only: bool = False
) -> str:
    """
    List all monitored domains.

    Args:
        limit: Maximum number of domains to return (default: 20)
        primary_only: Only show primary domains (default: False)

    Returns:
        JSON string with list of domains and their metadata
    """
    services = get_services()
    try:
        result = services['domain'].list_domains(
            limit=limit,
            primary_only=primary_only
        )

        # Format for readability
        domains = []
        for d in result.get('domains', []):
            domains.append({
                'domain': d.domain,
                'is_primary': d.is_primary,
                'scan_count': d.scan_count,
                'last_scanned': str(d.last_scanned_at) if d.last_scanned_at else None,
            })

        return json.dumps({
            'domains': domains,
            'total_count': result.get('total_count', len(domains)),
        }, indent=2)
    finally:
        services['db'].close()


@mcp.tool()
def get_domain_info(domain: str) -> str:
    """
    Get detailed information about a specific domain.

    Args:
        domain: The domain name to look up (e.g., "example.com")

    Returns:
        JSON string with domain details including subdomain count and recent activity
    """
    services = get_services()
    try:
        result = services['domain'].get_domain(domain)
        return json.dumps(result, indent=2, default=str)
    except DomainNotFound as e:
        return json.dumps({'error': str(e)})
    finally:
        services['db'].close()


@mcp.tool()
def add_domain(
    domain: str,
    is_primary: bool = False,
    contact_email: Optional[str] = None,
    scan_frequency: str = "weekly"
) -> str:
    """
    Add a new domain to monitor.

    Args:
        domain: Domain name to add (e.g., "example.com")
        is_primary: Mark as primary domain (default: False)
        contact_email: Contact email for notifications (optional)
        scan_frequency: How often to scan - hourly, daily, weekly, monthly (default: weekly)

    Returns:
        JSON string confirming domain was added
    """
    services = get_services()
    try:
        result = services['domain'].create_domain(
            domain=domain,
            is_primary=is_primary,
            contact_email=contact_email,
            scan_frequency=scan_frequency
        )
        return json.dumps({
            'success': True,
            'message': f'Domain {domain} added successfully',
            'domain': result.domain,
            'is_primary': result.is_primary,
        }, indent=2)
    except DomainAlreadyExists as e:
        return json.dumps({'error': str(e)})
    except Exception as e:
        return json.dumps({'error': f'Failed to add domain: {str(e)}'})
    finally:
        services['db'].close()


# =============================================================================
# Scan Tools
# =============================================================================

@mcp.tool()
def scan_domain(
    domain: str,
    timeout: int = 300
) -> str:
    """
    Start a security scan for a domain.

    This initiates an asynchronous scan that discovers subdomains,
    scans ports, probes HTTP services, checks TLS, and identifies vulnerabilities.

    Args:
        domain: Domain to scan (e.g., "example.com")
        timeout: Scan timeout in seconds (default: 300)

    Returns:
        JSON string with scan_id to track progress
    """
    services = get_services()
    try:
        result = services['scan'].create_and_queue_scan(
            domain=domain,
            timeout=timeout
        )
        return json.dumps({
            'success': True,
            'message': f'Scan started for {domain}',
            'scan_id': result['scan_id'],
            'status': 'pending',
            'note': 'Use get_scan_status to check progress'
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': f'Failed to start scan: {str(e)}'})
    finally:
        services['db'].close()


@mcp.tool()
def get_scan_status(scan_id: str) -> str:
    """
    Get the status of a scan.

    Args:
        scan_id: The scan ID returned from scan_domain

    Returns:
        JSON string with scan status (pending, running, completed, failed)
    """
    services = get_services()
    try:
        result = services['scan'].get_scan_status(scan_id)
        scan = result.get('scan', {})
        return json.dumps({
            'scan_id': scan.get('scan_id'),
            'domain': scan.get('domain'),
            'status': scan.get('status'),
            'findings_count': scan.get('findings_count', 0),
            'start_time': str(scan.get('start_time')) if scan.get('start_time') else None,
            'end_time': str(scan.get('end_time')) if scan.get('end_time') else None,
        }, indent=2)
    except ScanNotFound as e:
        return json.dumps({'error': str(e)})
    finally:
        services['db'].close()


@mcp.tool()
def get_scan_results(scan_id: str) -> str:
    """
    Get detailed results from a completed scan.

    Args:
        scan_id: The scan ID to get results for

    Returns:
        JSON string with discovered subdomains, open ports, and scan metadata
    """
    services = get_services()
    try:
        result = services['scan'].get_scan_results(scan_id)
        return json.dumps({
            'scan': result.get('scan'),
            'subdomains_count': len(result.get('subdomains', [])),
            'subdomains': result.get('subdomains', [])[:50],  # Limit to first 50
            'ports_count': len(result.get('ports', [])),
            'ports': result.get('ports', [])[:50],  # Limit to first 50
        }, indent=2, default=str)
    except ScanNotFound as e:
        return json.dumps({'error': str(e)})
    finally:
        services['db'].close()


@mcp.tool()
def list_scans(
    limit: int = 10,
    domain: Optional[str] = None
) -> str:
    """
    List recent scans.

    Args:
        limit: Maximum number of scans to return (default: 10)
        domain: Filter by domain name (optional)

    Returns:
        JSON string with list of recent scans
    """
    services = get_services()
    try:
        result = services['scan'].list_scans(limit=limit, domain=domain)
        return json.dumps({
            'scans': result.get('scans', []),
            'total_count': result.get('total_count', 0),
        }, indent=2, default=str)
    finally:
        services['db'].close()


# =============================================================================
# Findings Tools
# =============================================================================

@mcp.tool()
def get_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = 20
) -> str:
    """
    Get security findings from scans.

    Args:
        severity: Filter by minimum severity - critical, high, medium, low, info (optional)
        status: Filter by status - new, open, acknowledged, resolved, false_positive (optional)
        scan_id: Filter by specific scan ID (optional)
        limit: Maximum findings to return (default: 20)

    Returns:
        JSON string with list of findings
    """
    services = get_services()
    try:
        result = services['findings'].list_findings(
            min_severity=severity,
            status=status,
            scan_id=scan_id,
            limit=limit
        )

        findings = []
        for f in result.get('findings', []):
            findings.append({
                'id': f.get('id'),
                'title': f.get('title'),
                'severity': f.get('severity'),
                'status': f.get('status'),
                'affected_asset': f.get('affected_asset'),
                'finding_type': f.get('finding_type'),
                'risk_score': f.get('risk_score'),
            })

        return json.dumps({
            'findings': findings,
            'total': result.get('pagination', {}).get('total', len(findings)),
        }, indent=2)
    finally:
        services['db'].close()


@mcp.tool()
def get_finding_details(finding_id: str) -> str:
    """
    Get detailed information about a specific finding.

    Args:
        finding_id: The finding ID to look up

    Returns:
        JSON string with full finding details including description and remediation
    """
    services = get_services()
    try:
        result = services['findings'].get_finding(finding_id)
        return json.dumps(result, indent=2, default=str)
    except FindingNotFound as e:
        return json.dumps({'error': str(e)})
    finally:
        services['db'].close()


@mcp.tool()
def update_finding_status(
    finding_id: str,
    status: str,
    notes: Optional[str] = None
) -> str:
    """
    Update the status of a finding.

    Args:
        finding_id: The finding ID to update
        status: New status - open, acknowledged, resolved, false_positive
        notes: Optional resolution notes

    Returns:
        JSON string confirming the update
    """
    services = get_services()
    try:
        result = services['findings'].update_status(
            finding_id=finding_id,
            status=status,
            resolution_notes=notes
        )
        return json.dumps(result, indent=2)
    except FindingNotFound as e:
        return json.dumps({'error': str(e)})
    except InvalidFindingStatus as e:
        return json.dumps({'error': str(e)})
    finally:
        services['db'].close()


@mcp.tool()
def get_findings_stats(
    scan_id: Optional[str] = None,
    asset: Optional[str] = None
) -> str:
    """
    Get statistics about security findings.

    Args:
        scan_id: Filter stats for a specific scan (optional)
        asset: Filter stats for a specific asset/domain (optional)

    Returns:
        JSON string with severity breakdown and risk metrics
    """
    services = get_services()
    try:
        result = services['findings'].get_statistics(
            scan_id=scan_id,
            affected_asset=asset
        )
        return json.dumps(result, indent=2)
    finally:
        services['db'].close()


# =============================================================================
# MCP Resources
# =============================================================================

@mcp.resource("findings://stats")
def findings_stats_resource() -> str:
    """Current findings statistics across all scans."""
    services = get_services()
    try:
        stats = services['findings'].get_statistics()
        return json.dumps(stats, indent=2)
    finally:
        services['db'].close()


@mcp.resource("domains://list")
def domains_list_resource() -> str:
    """List of all monitored domains."""
    services = get_services()
    try:
        result = services['domain'].list_domains(limit=100)
        domains = [
            {
                'domain': d.domain,
                'is_primary': d.is_primary,
                'scan_count': d.scan_count,
            }
            for d in result.get('domains', [])
        ]
        return json.dumps({'domains': domains}, indent=2)
    finally:
        services['db'].close()


@mcp.resource("scans://recent")
def recent_scans_resource() -> str:
    """Recent scan activity (last 10 scans)."""
    services = get_services()
    try:
        result = services['scan'].list_scans(limit=10)
        return json.dumps(result, indent=2, default=str)
    finally:
        services['db'].close()


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    # Run with: python -m src.mcp.server
    mcp.run()
