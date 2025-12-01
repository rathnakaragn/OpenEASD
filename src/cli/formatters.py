"""Output formatters for CLI."""

import json
import csv
from io import StringIO
from typing import Dict, Any
from datetime import datetime


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def format_output(data: Dict[str, Any], format_type: str = 'table') -> str:
    """
    Format output data.

    Args:
        data: Data dictionary to format
        format_type: Output format (table, json, csv, txt)

    Returns:
        Formatted string
    """
    if format_type == 'json':
        return format_json_with_datetime(data)
    elif format_type == 'csv':
        return format_csv(data)
    elif format_type == 'txt':
        return format_txt(data)
    else:
        return format_table(data)


def format_json_with_datetime(data: Dict[str, Any]) -> str:
    """Format as JSON with datetime handling."""
    return json.dumps(data, indent=2, cls=DateTimeEncoder)


def format_json(data: Dict[str, Any]) -> str:
    """Format as JSON."""
    return json.dumps(data, indent=2)


def format_csv(data: Dict[str, Any]) -> str:
    """Format as CSV."""
    output = StringIO()

    if data.get('type') == 'scan_results':
        # Write subdomains
        if data.get('subdomains'):
            output.write("# Subdomains\n")
            writer = csv.writer(output)
            writer.writerow(['Subdomain'])
            for subdomain in data['subdomains']:
                writer.writerow([subdomain])
            output.write("\n")

        # Write ports
        if data.get('ports'):
            output.write("# Ports\n")
            writer = csv.writer(output)
            writer.writerow(['Subdomain', 'Port', 'Protocol', 'IP'])
            for port in data['ports']:
                writer.writerow([
                    port.get('subdomain', ''),
                    port.get('port', ''),
                    port.get('protocol', ''),
                    port.get('ip', '')
                ])

    elif data.get('type') == 'history':
        writer = csv.writer(output)
        writer.writerow(['Scan ID', 'Domain', 'Status', 'Subdomains', 'Ports', 'Start Time'])
        for scan in data.get('scans', []):
            writer.writerow([
                scan.get('scan_id', '')[:8],
                scan.get('domain', ''),
                scan.get('status', ''),
                scan.get('total_subdomains', 0),
                scan.get('total_ports', 0),
                scan.get('start_time', '')
            ])

    return output.getvalue()


def format_txt(data: Dict[str, Any]) -> str:
    """Format as plain text (subdomain list only)."""
    output = []

    if data.get('type') == 'scan_results':
        # For scan results, output just the subdomain names
        subdomains = data.get('subdomains', [])
        if subdomains:
            # Handle both list of strings and list of dicts
            for subdomain in subdomains:
                if isinstance(subdomain, dict):
                    subdomain_name = subdomain.get('subdomain', str(subdomain))
                else:
                    subdomain_name = subdomain
                output.append(subdomain_name)

        return '\n'.join(output)
    else:
        # For other types, fall back to table format
        return format_table(data)


def format_table(data: Dict[str, Any]) -> str:
    """Format as ASCII table."""
    output = []

    if data.get('type') == 'scan_results':
        # Check if this is results from 'results' command (nested scan dict) or 'scan' command (flat)
        scan_info = data.get('scan')
        if scan_info:
            # Results command format
            domain = scan_info.get('domain', 'Unknown')
            scan_id = scan_info.get('scan_id', 'N/A')
            start_time = scan_info.get('start_time', 'N/A')
            end_time = scan_info.get('end_time', 'N/A')
            status = scan_info.get('status', 'N/A')
            total_subdomains = scan_info.get('total_subdomains', 0)

            # Format timestamps
            if start_time != 'N/A' and 'T' in start_time:
                start_time = start_time.split('.')[0].replace('T', ' ')
            if end_time != 'N/A' and 'T' in end_time:
                end_time = end_time.split('.')[0].replace('T', ' ')
        else:
            # Scan command format (backward compatibility)
            domain = data.get('domain', 'Unknown')
            scan_id = data.get('scan_id', 'N/A')
            start_time = data.get('timestamp', 'N/A')
            end_time = 'N/A'
            status = 'completed'
            summary = data.get('summary', {})
            total_subdomains = summary.get('total_subdomains', 0)

        # Header
        output.append("=" * 80)
        output.append(f"Scan Results: {domain}")
        output.append("=" * 80)
        output.append(f"Scan ID:    {scan_id}")
        output.append(f"Status:     {status}")
        output.append(f"Start Time: {start_time}")
        if end_time != 'N/A':
            output.append(f"End Time:   {end_time}")
        output.append("")

        # Summary from enhanced scan
        summary = data.get('summary', {})
        active_count = summary.get('active_subdomains', 0)
        ports_count = summary.get('open_ports', 0)

        output.append(f"Total Subdomains Discovered: {total_subdomains}")
        if active_count > 0:
            output.append(f"Active Subdomains:           {active_count}")
        if ports_count > 0:
            output.append(f"Open Ports Found:            {ports_count}")
        output.append("")

        # Active Subdomains with IPs (if available)
        active_subdomains = data.get('active_subdomains', [])
        subdomain_ips = data.get('subdomain_ips', {})

        if active_subdomains:
            output.append("-" * 80)
            output.append(f"Active Subdomains ({len(active_subdomains)}):")
            output.append("-" * 80)
            for i, subdomain in enumerate(active_subdomains, 1):
                ips = subdomain_ips.get(subdomain, [])
                ip_str = ', '.join(ips[:3]) if ips else 'N/A'
                if len(ips) > 3:
                    ip_str += f' (+{len(ips) - 3} more)'
                output.append(f"  {i:3d}. {subdomain:<50} {ip_str}")
            output.append("")

        # Open Ports (if available)
        open_ports = data.get('open_ports', [])
        if open_ports:
            output.append("-" * 80)
            output.append(f"Open Ports ({len(open_ports)}):")
            output.append("-" * 80)
            output.append(f"  {'#':<5} {'Subdomain':<40} {'Port':<8} {'Proto':<8} {'IP':<15}")
            output.append("  " + "-" * 76)
            for i, port_info in enumerate(open_ports, 1):
                output.append(
                    f"  {i:<5} "
                    f"{port_info.get('subdomain', 'N/A'):<40} "
                    f"{port_info.get('port', 'N/A'):<8} "
                    f"{port_info.get('protocol', 'N/A'):<8} "
                    f"{port_info.get('ip', 'N/A'):<15}"
                )
            output.append("")

        # All Subdomains (collapsed view)
        subdomains = data.get('subdomains', [])
        if subdomains:
            output.append("-" * 80)
            output.append(f"All Discovered Subdomains ({len(subdomains)}):")
            output.append("-" * 80)
            # Handle both list of strings and list of dicts
            for i, subdomain in enumerate(subdomains, 1):
                if isinstance(subdomain, dict):
                    subdomain_name = subdomain.get('subdomain', str(subdomain))
                else:
                    subdomain_name = subdomain
                output.append(f"  {i:3d}. {subdomain_name}")
            output.append("")
        else:
            output.append("No subdomains discovered.")
            output.append("")

    elif data.get('type') == 'scan_list':
        # Header
        output.append("=" * 191)
        output.append("All Scan Sessions")
        output.append("=" * 191)

        scans = data.get('scans', [])

        if not scans:
            output.append("\nNo scans found.")
            output.append(data.get('message', ''))
        else:
            output.append("")
            output.append(f"{ 'Scan ID':<32} {'Tool':<12} {'Domain':<30} {'Status':<12} {'Findings':<10} {'Start Time':<20} {'End Time':<20} {'Duration':<10}")
            output.append("-" * 171)

            for scan in scans:
                scan_id = scan.get('scan_id', '')
                tool = scan.get('tool_name') or '-'
                domain = scan.get('domain', '')
                status = scan.get('status', '')
                findings = scan.get('findings_count', 0)
                start_time_raw = scan.get('start_time')
                end_time_raw = scan.get('end_time')

                # Calculate duration
                duration_str = 'N/A'
                if start_time_raw and end_time_raw:
                    try:
                        start_dt = datetime.fromisoformat(start_time_raw)
                        end_dt = datetime.fromisoformat(end_time_raw)
                        duration_seconds = int((end_dt - start_dt).total_seconds())
                        duration_str = f"{duration_seconds}s"
                    except:
                        duration_str = 'N/A'

                # Format timestamps for display
                start_time = start_time_raw or 'N/A'
                end_time = end_time_raw or 'N/A'
                if start_time != 'N/A' and 'T' in start_time:
                    start_time = start_time.split('.')[0].replace('T', ' ')
                if end_time != 'N/A' and 'T' in end_time:
                    end_time = end_time.split('.')[0].replace('T', ' ')

                output.append(
                    f"{scan_id:<32} "
                    f"{tool:<12} "
                    f"{domain:<30} "
                    f"{status:<12} "
                    f"{findings:<10} "
                    f"{start_time:<20} "
                    f"{end_time:<20} "
                    f"{duration_str:<10}"
                )

    elif data.get('type') == 'history':
        # Header
        output.append("=" * 150)
        output.append("Scan History")
        output.append("=" * 150)

        scans = data.get('scans', [])

        if not scans:
            output.append("\nNo scans found.")
            output.append(data.get('message', ''))
        else:
            output.append("")
            output.append(f"{ 'Domain':<30} {'Status':<12} {'Scans':<8} {'Subdomains':<12} {'First Scan':<20} {'Last Scan':<20}")
            output.append("-" * 130)

            for scan in scans:
                # Get subdomain count from findings_count for passive scans
                subdomain_count = scan.get('total_subdomains', 0)
                scan_count = scan.get('scan_count', 1)
                first_scan = scan.get('first_scan', 'N/A')
                last_scan = scan.get('last_scan', 'N/A')

                # Format timestamps to be more readable (remove microseconds)
                if first_scan != 'N/A' and 'T' in first_scan:
                    first_scan = first_scan.split('.')[0].replace('T', ' ')
                if last_scan != 'N/A' and 'T' in last_scan:
                    last_scan = last_scan.split('.')[0].replace('T', ' ')

                output.append(
                    f"{scan.get('domain', ''):<30} "
                    f"{scan.get('status', ''):<12} "
                    f"{scan_count:<8} "
                    f"{subdomain_count:<12} "
                    f"{first_scan:<20} "
                    f"{last_scan:<20}"
                )

    elif data.get('domains') is not None:
        # Domain list formatting
        domains = data.get('domains', [])
        total_count = data.get('total_count', len(domains))
        show_details = data.get('show_details', False)

        if not domains:
            output.append("=" * 150)
            output.append("Domains")
            output.append("=" * 150)
            output.append("\nNo domains found.")
        elif show_details:
            # Detailed view for each domain
            for idx, domain in enumerate(domains):
                if idx > 0:
                    output.append("\n")

                output.append("=" * 80)
                output.append(f"Domain Details - {domain.get('domain', 'Unknown')}")
                output.append("=" * 80)
                output.append(f"Domain:             {domain.get('domain', 'N/A')}")
                output.append(f"Primary:            {'Yes' if domain.get('is_primary') else 'No'}")
                output.append(f"Active Scan:        {'Enabled' if domain.get('active_scan_enabled') else 'Disabled'}")
                output.append(f"Scan Frequency:     {domain.get('scan_frequency') or 'Not set'}")
                output.append(f"Scan Count:         {domain.get('scan_count', 0)}")
                output.append(f"Contact Email:      {domain.get('contact_email') or 'Not set'}")
                output.append(f"Created:            {domain.get('created_at', 'N/A')}")
                output.append(f"Last Scanned:       {domain.get('last_scanned_at') or 'Never'}")
                output.append("")

                subdomain_count = domain.get('subdomain_count', 0)
                output.append(f"Total Subdomains: {subdomain_count}")

                recent_subdomains = domain.get('recent_subdomains', [])
                if recent_subdomains:
                    output.append("")
                    output.append("Recent Subdomains:")
                    output.append("-" * 80)
                    for sub in recent_subdomains[:5]:
                        status = sub.get('status', 'unknown')
                        subdomain = sub.get('subdomain', '')
                        last_seen = sub.get('last_seen', 'N/A')
                        output.append(f"  [{status:8s}] {subdomain} (last seen: {last_seen})")

            output.append("")
            output.append(f"Total: {total_count} domain(s)")
        else:
            # Table view (compact)
            output.append("=" * 100)
            output.append("Domains")
            output.append("=" * 100)
            output.append("")
            output.append(f"{ 'Domain':<35} {'Primary':<10} {'Scans':<8} {'Last Scanned':<30}")
            output.append("-" * 100)

            for domain in domains:
                domain_name = domain.get('domain', '')
                is_primary = '✓' if domain.get('is_primary') else ''
                scan_count = domain.get('scan_count', 0)
                last_scanned = domain.get('last_scanned_at')

                # Format last scanned date
                if last_scanned:
                    if isinstance(last_scanned, str) and 'T' in last_scanned:
                        last_scanned = last_scanned.split('.')[0].replace('T', ' ')
                else:
                    last_scanned = 'Never'

                output.append(
                    f"{domain_name:<35} "
                    f"{is_primary:<10} "
                    f"{scan_count:<8} "
                    f"{last_scanned:<30}"
                )

            output.append("")
            output.append(f"Total: {total_count} domain(s)")

    elif data.get('domain') is not None and not isinstance(data.get('domain'), str):
        # Single domain detail view
        domain = data.get('domain', {})

        output.append("=" * 80)
        output.append(f"Domain Details - {domain.get('domain', 'Unknown')}")
        output.append("=" * 80)
        output.append(f"Domain:             {domain.get('domain', 'N/A')}")
        output.append(f"Primary:            {'Yes' if domain.get('is_primary') else 'No'}")
        output.append(f"Active Scan:        {'Enabled' if domain.get('active_scan_enabled') else 'Disabled'}")
        output.append(f"Scan Frequency:     {domain.get('scan_frequency') or 'Not set'}")
        output.append(f"Scan Count:         {domain.get('scan_count', 0)}")
        output.append(f"Contact Email:      {domain.get('contact_email') or 'Not set'}")
        output.append(f"Created:            {domain.get('created_at', 'N/A')}")
        output.append(f"Last Scanned:       {domain.get('last_scanned_at') or 'Never'}")
        output.append("")

        subdomain_count = data.get('subdomain_count', 0)
        output.append(f"Total Subdomains: {subdomain_count}")

        recent_subdomains = data.get('recent_subdomains', [])
        if recent_subdomains:
            output.append("")
            output.append("Recent Subdomains:")
            output.append("-" * 80)
            for sub in recent_subdomains[:5]:
                status = sub.get('status', 'unknown')
                subdomain = sub.get('subdomain', '')
                last_seen = sub.get('last_seen', 'N/A')
                output.append(f"  [{status:8s}] {subdomain} (last seen: {last_seen})")

    elif data.get('type') == 'apikey_list':
        # API key list formatting
        api_keys = data.get('api_keys', [])
        total = data.get('total', len(api_keys))

        output.append("=" * 100)
        output.append("API Keys")
        output.append("=" * 100)

        if not api_keys:
            output.append("\nNo API keys found.")
        else:
            output.append("")
            output.append(f"{'ID':<40} {'Name':<20} {'Active':<8} {'Created':<20}")
            output.append("-" * 100)

            for key in api_keys:
                key_id = key.get('id', '')
                name = key.get('name', '')
                is_active = '✓' if key.get('is_active') else '✗'
                created_at = key.get('created_at', 'N/A')

                # Format timestamp
                if created_at and hasattr(created_at, 'isoformat'):
                    created_at = created_at.isoformat()
                if created_at and 'T' in str(created_at):
                    created_at = str(created_at).split('.')[0].replace('T', ' ')

                output.append(f"{key_id:<40} {name:<20} {is_active:<8} {created_at:<20}")

            output.append("")
            output.append(f"Total: {total} API key(s)")

    output.append("")
    return "\n".join(output)