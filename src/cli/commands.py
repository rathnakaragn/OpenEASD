"""CLI command implementations."""

import subprocess
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from src.data.database.duckdb_manager import DuckDBManager
from src.data.database.organization_manager import OrganizationManager
from src.utils.timezone import get_ist_now


def run_subfinder(domain: str, timeout: int = 300) -> List[str]:
    """
    Run subfinder to discover subdomains.

    Args:
        domain: Domain to scan
        timeout: Command timeout in seconds

    Returns:
        List of discovered subdomains
    """
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent', '-json'],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        subdomains = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.append(data['host'])
                except json.JSONDecodeError:
                    continue

        return subdomains

    except subprocess.TimeoutExpired:
        raise Exception(f"Subfinder timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("Subfinder not found. Please install: https://github.com/projectdiscovery/subfinder")


def run_naabu(targets: List[str], top_ports: int = 1000, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run naabu to scan ports.

    Args:
        targets: List of hosts to scan
        top_ports: Number of top ports to scan
        timeout: Command timeout in seconds

    Returns:
        List of port dictionaries
    """
    if not targets:
        return []

    try:
        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        result = subprocess.run(
            ['naabu', '-list', targets_file, '-top-ports', str(top_ports), '-json', '-silent'],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Clean up temp file
        Path(targets_file).unlink(missing_ok=True)

        ports = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    ports.append({
                        'subdomain': data.get('host', ''),
                        'port': data.get('port', 0),
                        'protocol': data.get('protocol', 'tcp'),
                        'ip': data.get('ip', '')
                    })
                except json.JSONDecodeError:
                    continue

        return ports

    except subprocess.TimeoutExpired:
        raise Exception(f"Naabu timed out after {timeout} seconds")
    except FileNotFoundError:
        raise Exception("Naabu not found. Please install: https://github.com/projectdiscovery/naabu")


def scan_command(args) -> Dict[str, Any]:
    """
    Execute passive subdomain enumeration scan.

    Args:
        args: Parsed command arguments

    Returns:
        Scan results dictionary
    """
    domain = args.domain
    timeout = args.timeout
    save = args.save
    organization = args.organization if args.organization else domain.split('.')[0].title()

    print(f"[*] Starting passive subdomain enumeration for: {domain}")
    print(f"[*] Organization: {organization}")
    print()

    # Initialize storage if saving
    db_manager = None
    org_manager = None
    scan_id = None

    if save:
        # Initialize organization manager
        org_manager = OrganizationManager()
        asyncio.run(org_manager.initialize())

        # Create organization if doesn't exist
        if not asyncio.run(org_manager.organization_exists(organization)):
            print(f"[*] Creating new organization: {organization}")
            result = asyncio.run(org_manager.create_organization(organization))
            print(f"[+] {result['message']}")
            print()

        # Get organization-specific database path
        db_path = asyncio.run(org_manager.get_organization_db_path(organization))

        # Initialize org-specific database manager
        db_manager = DuckDBManager(organization, db_path)
        asyncio.run(db_manager.initialize())

        scan_id = asyncio.run(db_manager.create_scan_session('passive_subdomain_enum', [domain]))
        print(f"[*] Scan ID: {scan_id}")
        print()

    try:
        # Passive subdomain discovery
        print("[*] Discovering subdomains (passive enumeration)...")
        subdomains = run_subfinder(domain, timeout)
        print(f"[+] Found {len(subdomains)} subdomains")
        print()

        # Add domain to database if saving (skip if already exists)
        if save and db_manager:
            domain_exists = asyncio.run(db_manager.domain_exists(domain))
            if not domain_exists:
                asyncio.run(db_manager.add_domain(domain, is_primary=True))

        # Save results and update scan status
        if save and db_manager and scan_id:
            # Store subdomains as findings
            alerts = []
            for subdomain in subdomains:
                alerts.append({
                    'domain': subdomain,
                    'scan_id': scan_id,
                    'vulnerability_type': 'subdomain_discovered',
                    'severity': 'info',
                    'description': f"Subdomain discovered: {subdomain}",
                    'tool_source': 'subfinder',
                    'discovered_at': get_ist_now()
                })

            if alerts:
                asyncio.run(db_manager.store_alerts(alerts))

            asyncio.run(db_manager.update_scan_status(
                scan_id,
                'completed',
                end_time=get_ist_now(),
                findings_count=len(subdomains)
            ))

        # Return results
        result = {
            'type': 'scan_results',
            'scan_id': scan_id,
            'domain': domain,
            'timestamp': get_ist_now().isoformat(),
            'subdomains': subdomains,
            'summary': {
                'total_subdomains': len(subdomains)
            }
        }

        return result

    except Exception as e:
        if save and db_manager and scan_id:
            asyncio.run(db_manager.update_scan_status(
                scan_id,
                'failed',
                end_time=get_ist_now()
            ))
        raise

    finally:
        if db_manager:
            asyncio.run(db_manager.close())


def history_command(args) -> Dict[str, Any]:
    """
    Execute history command - queries across all organizations or filtered by org.

    Args:
        args: Parsed command arguments

    Returns:
        Scan history dictionary
    """
    async def _get_history():
        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get all organizations
            orgs = await org_manager.list_organizations()

            if not orgs:
                return {
                    'type': 'history',
                    'scans': [],
                    'message': 'No organizations found. Run scans to create history.'
                }

            # Filter by organization if specified
            filter_org = getattr(args, 'filter_org', None)
            if filter_org:
                orgs = [org for org in orgs if org['org_name'].lower() == filter_org.lower()]
                if not orgs:
                    return {
                        'type': 'history',
                        'scans': [],
                        'message': f'Organization not found: {filter_org}'
                    }

            all_scans = []

            # Query each organization database
            for org in orgs:
                db_manager = DuckDBManager(org['org_name'], org['db_path'])
                await db_manager.initialize()

                try:
                    # Get domain scan summary for this org
                    def _get_recent_scans():
                        result = db_manager.connection.execute("""
                            SELECT
                                d.domain,
                                COUNT(DISTINCT s.scan_id) as scan_count,
                                MAX(CASE WHEN s.status = 'completed' THEN s.findings_count ELSE 0 END) as subdomains,
                                MIN(s.start_time) as first_scan,
                                MAX(s.start_time) as last_scan,
                                MAX(CASE WHEN s.status = 'completed' THEN 'completed' ELSE s.status END) as status
                            FROM domains d
                            LEFT JOIN scan_sessions s ON s.domains_scanned[1] = d.domain
                            GROUP BY d.domain
                            ORDER BY MAX(s.start_time) DESC
                        """).fetchall()

                        scans = []
                        for row in result:
                            scans.append({
                                'organization': org['org_name'],
                                'domain': row[0],
                                'scan_count': row[1] or 0,
                                'total_subdomains': row[2] or 0,
                                'first_scan': row[3].isoformat() if row[3] else 'N/A',
                                'last_scan': row[4].isoformat() if row[4] else 'N/A',
                                'status': row[5] if row[5] else 'pending',
                                'total_ports': row[2] or 0  # For compatibility
                            })
                        return scans

                    scans = await asyncio.get_event_loop().run_in_executor(None, _get_recent_scans)
                    all_scans.extend(scans)

                finally:
                    await db_manager.close()

            # Sort all scans by last_scan date (newest first)
            all_scans.sort(key=lambda x: x['last_scan'], reverse=True)

            # Limit results
            limited_scans = all_scans[:args.limit]

            return {
                'type': 'history',
                'scans': limited_scans
            }

        finally:
            await org_manager.close()

    return asyncio.run(_get_history())


def results_command(args) -> Dict[str, Any]:
    """
    Execute results command - searches for scan across all organizations or filtered by org.

    Args:
        args: Parsed command arguments

    Returns:
        Scan results dictionary
    """
    async def _get_results():
        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get all organizations
            orgs = await org_manager.list_organizations()

            if not orgs:
                raise Exception("No organizations found. No scans have been saved yet.")

            # Filter by organization if specified
            filter_org = getattr(args, 'filter_org', None)
            if filter_org:
                orgs = [org for org in orgs if org['org_name'].lower() == filter_org.lower()]
                if not orgs:
                    raise Exception(f"Organization not found: {filter_org}")

            # Search for scan across organizations
            scan_info = None
            found_org = None
            found_db_manager = None

            for org in orgs:
                db_manager = DuckDBManager(org['org_name'], org['db_path'])
                await db_manager.initialize()

                try:
                    # Try to find scan in this org's database
                    info = await db_manager.get_scan_status(args.scan_id)

                    if info:
                        scan_info = info
                        found_org = org
                        found_db_manager = db_manager
                        break
                    else:
                        await db_manager.close()

                except Exception:
                    await db_manager.close()
                    continue

            if not scan_info or not found_db_manager:
                raise Exception(f"Scan ID not found: {args.scan_id}")

            try:
                # Get alerts (subdomains/ports) for this scan
                def _get_scan_alerts():
                    result = found_db_manager.connection.execute("""
                        SELECT domain, vulnerability_type, severity, description, tool_source, discovered_at
                        FROM security_alerts
                        WHERE scan_id = ?
                        ORDER BY domain, description
                    """, [args.scan_id]).fetchall()

                    ports = []
                    subdomains = set()
                    for row in result:
                        subdomain = row[0]
                        subdomains.add(subdomain)

                        # Parse port from description (e.g., "Open port 80 (tcp)")
                        port_num = 0
                        protocol = 'tcp'
                        desc = row[3] or ''
                        if 'Open port' in desc:
                            parts = desc.replace('Open port ', '').split(' ')
                            try:
                                port_num = int(parts[0])
                                if len(parts) > 1:
                                    protocol = parts[1].strip('()')
                            except:
                                pass

                        ports.append({
                            'subdomain': subdomain,
                            'port': port_num,
                            'protocol': protocol,
                            'ip': '',
                            'discovered_at': row[5].isoformat() if row[5] else ''
                        })

                    return {
                        'subdomains': [{'subdomain': s, 'ip_address': '', 'discovered_at': ''} for s in sorted(subdomains)],
                        'ports': ports
                    }

                scan_data = await asyncio.get_event_loop().run_in_executor(None, _get_scan_alerts)

                return {
                    'type': 'scan_results',
                    'scan': {
                        'scan_id': scan_info['scan_id'],
                        'organization': found_org['org_name'],
                        'domain': scan_info['domains'][0] if scan_info['domains'] else '',
                        'start_time': scan_info['start_time'].isoformat() if scan_info['start_time'] else '',
                        'end_time': scan_info['end_time'].isoformat() if scan_info['end_time'] else '',
                        'status': scan_info['status'],
                        'total_subdomains': len(scan_data['subdomains']),
                        'total_ports': scan_info['findings_count']
                    },
                    'subdomains': scan_data['subdomains'],
                    'ports': scan_data['ports']
                }

            finally:
                await found_db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_get_results())


def delete_command(args) -> Dict[str, Any]:
    """
    Execute delete command - deletes organization or domain.

    Args:
        args: Parsed command arguments

    Returns:
        Deletion results dictionary
    """
    organization = args.organization
    domain = args.domain
    force = args.force

    if not organization and not domain:
        raise Exception("Must specify either --org or --domain")

    if organization and domain:
        raise Exception("Cannot specify both --org and --domain. Choose one.")

    async def _delete_data():
        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            if organization:
                # Delete entire organization
                org_info = await org_manager.get_organization_info(organization)

                if not org_info:
                    return {
                        'type': 'delete_result',
                        'success': False,
                        'message': f"Organization not found: {organization}"
                    }

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

                    print(f"\nPreview of deletion for organization: {organization}")
                    print("=" * 60)
                    print(f"This will permanently delete:")
                    print(f"  - {counts['domains']} domain(s)")
                    print(f"  - {counts['alerts']} security alert(s)")
                    print(f"  - {counts['scans']} scan session(s)")
                    print(f"  - Organization database: {org_info['db_path']}")

                finally:
                    await db_manager.close()

                # Confirm deletion
                if not force:
                    print(f"\nAre you sure you want to delete? This cannot be undone. [y/N]: ", end='')
                    confirmation = input().strip().lower()

                    if confirmation != 'y':
                        return {
                            'type': 'delete_result',
                            'success': False,
                            'message': 'Deletion cancelled by user'
                        }

                # Delete organization
                print("\nDeleting...")
                result = await org_manager.delete_organization(organization, force=True)

                if result['success']:
                    print(f"✓ Deleted organization: {organization}")
                    print(f"✓ Deleted database: {result['db_path']}")

                return {
                    'type': 'delete_result',
                    'success': result['success'],
                    'target_type': 'organization',
                    'target_name': organization,
                    'message': result['message']
                }

            else:
                # Delete domain from its organization
                # First, find which organization owns the domain
                found_org = await org_manager.find_org_for_domain(domain)

                if not found_org:
                    return {
                        'type': 'delete_result',
                        'success': False,
                        'message': f"Domain not found: {domain}"
                    }

                # Get org database path
                db_path = await org_manager.get_organization_db_path(found_org)

                # Delete domain from org database
                db_manager = DuckDBManager(found_org, db_path)
                await db_manager.initialize()

                try:
                    # Get deletion preview
                    preview = await db_manager.get_deletion_preview(domain=domain)

                    if 'error' in preview:
                        raise Exception(preview['error'])

                    if preview['total_domains'] == 0:
                        return {
                            'type': 'delete_result',
                            'success': False,
                            'message': f"No data found for domain: {domain}"
                        }

                    # Show preview
                    print(f"\nPreview of deletion for domain: {domain}")
                    print(f"Organization: {found_org}")
                    print("=" * 60)

                    for dom_info in preview['domains']:
                        print(f"  - {dom_info['domain']}")
                        print(f"    └─ Security alerts: {dom_info['alerts']}")
                        print(f"    └─ Scan sessions: {dom_info['scans']}")

                    print(f"\nThis will permanently delete:")
                    print(f"  - {preview['total_domains']} domain(s)")
                    print(f"  - {preview['total_alerts']} security alert(s)")
                    print(f"  - {preview['total_scans']} scan session(s)")

                    # Confirm deletion
                    if not force:
                        print(f"\nAre you sure you want to delete? This cannot be undone. [y/N]: ", end='')
                        confirmation = input().strip().lower()

                        if confirmation != 'y':
                            return {
                                'type': 'delete_result',
                                'success': False,
                                'message': 'Deletion cancelled by user'
                            }

                    # Perform deletion
                    print("\nDeleting...")
                    result = await db_manager.delete_domain_with_data(domain)

                    print(f"✓ Deleted {result['alerts']} security alerts")
                    print(f"✓ Deleted {result['scans']} scan sessions")
                    print(f"✓ Deleted {result['domains']} domains")

                    return {
                        'type': 'delete_result',
                        'success': True,
                        'target_type': 'domain',
                        'target_name': domain,
                        'organization': found_org,
                        'deleted': result,
                        'message': f"Successfully deleted domain: {domain} from organization: {found_org}"
                    }

                finally:
                    await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_delete_data())


def view_scans_command(args) -> Dict[str, Any]:
    """
    Execute view scans command - lists all scan IDs across all organizations or filtered by org.

    Args:
        args: Parsed command arguments

    Returns:
        Scan list dictionary
    """
    async def _get_scans():
        # Initialize organization manager
        org_manager = OrganizationManager()
        await org_manager.initialize()

        try:
            # Get all organizations
            orgs = await org_manager.list_organizations()

            if not orgs:
                return {
                    'type': 'scan_list',
                    'scans': [],
                    'message': 'No organizations found. Run scans to create history.'
                }

            # Filter by organization if specified
            filter_org = getattr(args, 'filter_org', None)
            if filter_org:
                orgs = [org for org in orgs if org['org_name'].lower() == filter_org.lower()]
                if not orgs:
                    return {
                        'type': 'scan_list',
                        'scans': [],
                        'message': f'Organization not found: {filter_org}'
                    }

            all_scans = []

            # Query each organization database
            for org in orgs:
                db_manager = DuckDBManager(org['org_name'], org['db_path'])
                await db_manager.initialize()

                try:
                    def _get_all_scans():
                        result = db_manager.connection.execute("""
                            SELECT
                                s.scan_id,
                                s.scan_type,
                                s.tool_name,
                                s.domains_scanned[1] as domain,
                                s.status,
                                s.findings_count,
                                s.start_time,
                                s.end_time
                            FROM scan_sessions s
                            ORDER BY s.start_time DESC
                        """).fetchall()

                        scans = []
                        for row in result:
                            scans.append({
                                'scan_id': row[0],
                                'scan_type': row[1],
                                'tool_name': row[2],
                                'domain': row[3],
                                'organization': org['org_name'],
                                'status': row[4],
                                'findings_count': row[5] if row[5] else 0,
                                'start_time': row[6].isoformat() if row[6] else 'N/A',
                                'end_time': row[7].isoformat() if row[7] else 'N/A'
                            })
                        return scans

                    scans = await asyncio.get_event_loop().run_in_executor(None, _get_all_scans)
                    all_scans.extend(scans)

                finally:
                    await db_manager.close()

            # Sort all scans by start_time (newest first)
            all_scans.sort(key=lambda x: x['start_time'], reverse=True)

            # Limit results
            limited_scans = all_scans[:args.limit]

            return {
                'type': 'scan_list',
                'scans': limited_scans
            }

        finally:
            await org_manager.close()

    return asyncio.run(_get_scans())


def batch_scan_subfinder_command(args) -> Dict[str, Any]:
    """
    Execute batch subfinder scan for all domains in the default organization.

    Args:
        args: Parsed command arguments

    Returns:
        Batch scan results dictionary
    """
    async def _batch_scan():
        from src.utils.config import Config

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
                    'success': False,
                    'message': f'Organization not found: {organization}'
                }

            # Get organization database path
            db_path = await org_manager.get_organization_db_path(organization)

            # Initialize database manager
            db_manager = DuckDBManager(organization, db_path)
            await db_manager.initialize()

            try:
                # Get all apex domains (optionally filter by primary)
                primary_only = getattr(args, 'primary', False)
                domain_type = 'apex'

                result = await db_manager.get_domains(
                    limit=1000,  # Large limit to get all domains
                    domain_type=domain_type,
                    primary_only=primary_only
                )

                domains = result['domains']

                if not domains:
                    return {
                        'success': True,
                        'type': 'batch_scan',
                        'organization': organization,
                        'message': f'No domains found in {organization}',
                        'scans': [],
                        'total_domains': 0,
                        'successful_scans': 0,
                        'failed_scans': 0
                    }

                print(f"[*] Starting batch subfinder scan for organization: {organization}")
                print(f"[*] Found {len(domains)} domain(s) to scan")
                if primary_only:
                    print(f"[*] Scanning primary domains only")
                print()

                # Prepare scan results
                scan_results = []
                successful_scans = 0
                failed_scans = 0
                timeout = getattr(args, 'timeout', 300)

                # Scan each domain
                for idx, domain_info in enumerate(domains, 1):
                    domain = domain_info['domain']
                    print(f"[{idx}/{len(domains)}] Scanning: {domain}")
                    print("-" * 60)

                    # Create a new scan session for this domain
                    scan_id = None
                    domain_db_manager = DuckDBManager(organization, db_path)
                    await domain_db_manager.initialize()

                    try:
                        # Create scan session
                        scan_id = await domain_db_manager.create_scan_session(
                            scan_type='passive_subdomain_enum',
                            domains=[domain],
                            tool_name='subfinder'
                        )
                        print(f"[*] Scan ID: {scan_id}")
                        print()

                        # Run subfinder
                        print("[*] Discovering subdomains (passive enumeration)...")
                        subdomains = run_subfinder(domain, timeout)
                        print(f"[+] Found {len(subdomains)} subdomains")
                        print()

                        # Ensure domain exists in database
                        domain_exists = await domain_db_manager.domain_exists(domain)
                        if not domain_exists:
                            await domain_db_manager.add_domain(domain, is_primary=domain_info.get('is_primary', False))

                        # Store subdomains in tool-specific table (detailed)
                        subfinder_results = []
                        for subdomain in subdomains:
                            subfinder_results.append({
                                'scan_id': scan_id,
                                'apex_domain': domain,
                                'subdomain': subdomain,
                                'source': 'subfinder',  # Could be enhanced with actual source
                                'discovered_at': get_ist_now(),
                                'raw_json': None  # TODO: Store raw JSON if available
                            })

                        if subfinder_results:
                            await domain_db_manager.store_subfinder_results(subfinder_results)

                        # Store subdomains as alerts (summary)
                        alerts = []
                        for subdomain in subdomains:
                            alerts.append({
                                'domain': subdomain,
                                'scan_id': scan_id,
                                'vulnerability_type': 'subdomain_discovered',
                                'severity': 'info',
                                'description': f"Subdomain discovered: {subdomain}",
                                'tool_source': 'subfinder',
                                'discovered_at': get_ist_now()
                            })

                        if alerts:
                            await domain_db_manager.store_alerts(alerts)

                        # Update scan status
                        await domain_db_manager.update_scan_status(
                            scan_id,
                            'completed',
                            end_time=get_ist_now(),
                            findings_count=len(subdomains)
                        )

                        scan_results.append({
                            'domain': domain,
                            'status': 'success',
                            'scan_id': scan_id,
                            'subdomains': len(subdomains)
                        })

                        successful_scans += 1
                        print(f"[+] Scan completed: {domain}")

                    except Exception as e:
                        # Update scan status to failed if scan_id exists
                        if scan_id:
                            try:
                                await domain_db_manager.update_scan_status(
                                    scan_id,
                                    'failed',
                                    end_time=get_ist_now()
                                )
                            except:
                                pass

                        scan_results.append({
                            'domain': domain,
                            'status': 'failed',
                            'error': str(e)
                        })

                        failed_scans += 1
                        print(f"[-] Scan failed: {domain} - {str(e)}")

                    finally:
                        await domain_db_manager.close()

                    print()

                return {
                    'success': True,
                    'type': 'batch_scan',
                    'organization': organization,
                    'scans': scan_results,
                    'total_domains': len(domains),
                    'successful_scans': successful_scans,
                    'failed_scans': failed_scans
                }

            finally:
                await db_manager.close()

        finally:
            await org_manager.close()

    return asyncio.run(_batch_scan())
