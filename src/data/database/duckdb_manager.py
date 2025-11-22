"""
DuckDB implementation of DatabaseManager interface.

Multi-organization database implementation with isolated databases per org.
"""

import asyncio
import duckdb
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path

from src.core.interfaces.database import DatabaseManager
from src.utils.timezone import get_ist_now, to_ist, utc_to_ist


class DuckDBManager(DatabaseManager):
    """
    DuckDB implementation of DatabaseManager interface.

    Multi-org aware: Each organization has its own database file.
    """

    def __init__(self, organization: str, db_path: Optional[str] = None):
        """
        Initialize DuckDB manager with organization context.

        Args:
            organization: Organization name
            db_path: Optional explicit database path. If not provided, will be
                    resolved from OrganizationManager based on organization name.
        """
        self.organization = organization
        self.db_path = db_path or os.getenv('OPENEASD_DB_PATH', 'data/openeasd.db')
        self.connection = None
        self._ensure_data_directory()
    
    def _ensure_data_directory(self):
        """Ensure the data directory exists."""
        data_dir = Path(self.db_path).parent
        data_dir.mkdir(parents=True, exist_ok=True)

    def _migrate_domains_table(self):
        """Migrate domains table from old schema to new schema."""
        print(f"Migrating domains table schema for {self.organization}...")

        # Create temporary table with new schema
        self.connection.execute("""
            CREATE TABLE domains_new (
                domain VARCHAR PRIMARY KEY,
                domain_type VARCHAR CHECK (domain_type IN ('apex', 'subdomain')) DEFAULT 'apex',
                is_primary BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned_at TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                -- Metadata fields
                notes TEXT,
                tags VARCHAR[],
                contact_email VARCHAR,
                scan_frequency VARCHAR,
                active_scan_enabled BOOLEAN DEFAULT TRUE
            )
        """)

        # Copy data from old table to new table
        self.connection.execute("""
            INSERT INTO domains_new (domain, is_primary, created_at, updated_at)
            SELECT domain, is_primary, created_at, created_at as updated_at
            FROM domains
        """)

        # Drop old table and rename new table
        self.connection.execute("DROP TABLE domains")
        self.connection.execute("ALTER TABLE domains_new RENAME TO domains")

        print(f"✓ Migration complete for {self.organization}")

    async def initialize(self) -> None:
        """Initialize the database connection and create tables."""
        # DuckDB operations are synchronous, but we wrap in async for interface compliance
        await asyncio.get_event_loop().run_in_executor(None, self._initialize_sync)
    
    def _initialize_sync(self):
        """Synchronous database initialization."""
        self.connection = duckdb.connect(self.db_path)

        # Check if domains table exists and needs migration
        try:
            result = self.connection.execute(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'domains'"
            ).fetchone()

            if result[0] > 0:
                # Table exists, check if it needs migration
                columns = self.connection.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'domains'"
                ).fetchall()
                column_names = [col[0] for col in columns]

                # If domain_type column doesn't exist, we need to migrate
                if 'domain_type' not in column_names:
                    self._migrate_domains_table()
            else:
                # Create new table with full schema
                self.connection.execute("""
                    CREATE TABLE domains (
                        domain VARCHAR PRIMARY KEY,
                        domain_type VARCHAR CHECK (domain_type IN ('apex', 'subdomain')) DEFAULT 'apex',
                        is_primary BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_scanned_at TIMESTAMP,
                        scan_count INTEGER DEFAULT 0,
                        -- Metadata fields
                        notes TEXT,
                        tags VARCHAR[],
                        contact_email VARCHAR,
                        scan_frequency VARCHAR,
                        active_scan_enabled BOOLEAN DEFAULT TRUE
                    )
                """)
        except Exception as e:
            # If any error, try creating the table with IF NOT EXISTS
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    domain VARCHAR PRIMARY KEY,
                    domain_type VARCHAR CHECK (domain_type IN ('apex', 'subdomain')) DEFAULT 'apex',
                    is_primary BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scanned_at TIMESTAMP,
                    scan_count INTEGER DEFAULT 0,
                    -- Metadata fields
                    notes TEXT,
                    tags VARCHAR[],
                    contact_email VARCHAR,
                    scan_frequency VARCHAR,
                    active_scan_enabled BOOLEAN DEFAULT TRUE
                )
            """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS subdomain_history (
                id VARCHAR PRIMARY KEY,
                apex_domain VARCHAR NOT NULL,
                subdomain VARCHAR NOT NULL,
                scan_id VARCHAR NOT NULL,
                status VARCHAR CHECK (status IN ('new', 'existing', 'removed')) NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tool_source VARCHAR,
                metadata TEXT,
                -- For change tracking
                UNIQUE(subdomain, scan_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id VARCHAR PRIMARY KEY,
                domain VARCHAR NOT NULL,
                scan_id VARCHAR,
                vulnerability_type VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                description TEXT,
                remediation TEXT,
                tool_source VARCHAR,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                scan_id VARCHAR PRIMARY KEY,
                scan_type VARCHAR NOT NULL,
                tool_name VARCHAR,
                domains_scanned VARCHAR[],
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status VARCHAR DEFAULT 'queued',
                findings_count INTEGER DEFAULT 0
            )
        """)

        # Tool-specific result tables
        # Note: Foreign key constraints removed for DuckDB compatibility
        # Referential integrity maintained through application logic
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS subfinder_results (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                apex_domain VARCHAR NOT NULL,
                subdomain VARCHAR NOT NULL,
                source VARCHAR,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS amass_results (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                apex_domain VARCHAR NOT NULL,
                subdomain VARCHAR NOT NULL,
                ip_address VARCHAR,
                cidr VARCHAR,
                asn INTEGER,
                sources VARCHAR[],
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS nmap_results (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                host VARCHAR NOT NULL,
                port INTEGER NOT NULL,
                protocol VARCHAR,
                state VARCHAR,
                service VARCHAR,
                service_version VARCHAR,
                os_info TEXT,
                cpe VARCHAR,
                scripts_output TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_xml TEXT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS naabu_results (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                host VARCHAR NOT NULL,
                port INTEGER NOT NULL,
                protocol VARCHAR,
                ip VARCHAR,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT
            )
        """)

        # Tool-specific history tables
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS subfinder_history (
                id VARCHAR PRIMARY KEY,
                apex_domain VARCHAR NOT NULL,
                subdomain VARCHAR NOT NULL,
                scan_id VARCHAR NOT NULL,
                status VARCHAR CHECK (status IN ('new', 'existing', 'removed')) NOT NULL,
                source VARCHAR,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subdomain, scan_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS amass_history (
                id VARCHAR PRIMARY KEY,
                apex_domain VARCHAR NOT NULL,
                subdomain VARCHAR NOT NULL,
                scan_id VARCHAR NOT NULL,
                status VARCHAR CHECK (status IN ('new', 'existing', 'removed')) NOT NULL,
                ip_address VARCHAR,
                sources VARCHAR[],
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subdomain, scan_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS nmap_history (
                id VARCHAR PRIMARY KEY,
                host VARCHAR NOT NULL,
                port INTEGER NOT NULL,
                scan_id VARCHAR NOT NULL,
                status VARCHAR CHECK (status IN ('new', 'existing', 'removed', 'changed')) NOT NULL,
                service VARCHAR,
                service_version VARCHAR,
                previous_version VARCHAR,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, port, scan_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS naabu_history (
                id VARCHAR PRIMARY KEY,
                host VARCHAR NOT NULL,
                port INTEGER NOT NULL,
                scan_id VARCHAR NOT NULL,
                status VARCHAR CHECK (status IN ('new', 'existing', 'removed')) NOT NULL,
                protocol VARCHAR,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, port, scan_id)
            )
        """)

        # Create indexes for better performance
        # Domain indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_domains_type ON domains(domain_type)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_domains_primary ON domains(is_primary)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_domains_last_scanned ON domains(last_scanned_at)")

        # Subdomain history indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subdomain_history_apex ON subdomain_history(apex_domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subdomain_history_scan ON subdomain_history(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subdomain_history_status ON subdomain_history(status)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subdomain_history_subdomain ON subdomain_history(subdomain)")

        # Security alerts indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_domain ON security_alerts(domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_scan_id ON security_alerts(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_discovered ON security_alerts(discovered_at)")

        # Scan sessions indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_sessions(status)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scan_sessions(start_time)")

        # Tool-specific result table indexes
        # Subfinder indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_scan_id ON subfinder_results(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_apex ON subfinder_results(apex_domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_subdomain ON subfinder_results(subdomain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_discovered ON subfinder_results(discovered_at)")

        # Amass indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_scan_id ON amass_results(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_apex ON amass_results(apex_domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_subdomain ON amass_results(subdomain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_ip ON amass_results(ip_address)")

        # Nmap indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_scan_id ON nmap_results(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_host ON nmap_results(host)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_port ON nmap_results(port)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_service ON nmap_results(service)")

        # Naabu indexes
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_scan_id ON naabu_results(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_host ON naabu_results(host)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_port ON naabu_results(port)")

        # Tool-specific history table indexes
        # Subfinder history
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_hist_apex ON subfinder_history(apex_domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_hist_scan ON subfinder_history(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_subfinder_hist_status ON subfinder_history(status)")

        # Amass history
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_hist_apex ON amass_history(apex_domain)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_hist_scan ON amass_history(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_amass_hist_status ON amass_history(status)")

        # Nmap history
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_hist_host ON nmap_history(host)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_hist_scan ON nmap_history(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_nmap_hist_status ON nmap_history(status)")

        # Naabu history
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_hist_host ON naabu_history(host)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_hist_scan ON naabu_history(scan_id)")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_naabu_hist_status ON naabu_history(status)")
    
    async def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            await asyncio.get_event_loop().run_in_executor(None, self.connection.close)
            self.connection = None
    
    # Domain Management
    async def add_domain(self, domain: str, is_primary: bool = False,
                        domain_type: str = 'apex',
                        notes: Optional[str] = None,
                        tags: Optional[List[str]] = None,
                        contact_email: Optional[str] = None,
                        scan_frequency: Optional[str] = None,
                        active_scan_enabled: bool = True) -> Dict[str, Any]:
        """
        Add a domain to tracking.

        Args:
            domain: Domain name
            is_primary: Whether this is a primary domain
            domain_type: Type of domain ('apex' or 'subdomain')
            notes: Optional notes about the domain
            tags: Optional tags for categorization
            contact_email: Contact email for this domain
            scan_frequency: Scan frequency preference
            active_scan_enabled: Whether active scanning is enabled

        Note: No organization parameter needed - this database belongs to one org.
        """
        def _add_domain():
            ist_now = get_ist_now()
            self.connection.execute(
                """INSERT INTO domains
                   (domain, domain_type, is_primary, created_at, updated_at, notes, tags,
                    contact_email, scan_frequency, active_scan_enabled)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [domain, domain_type, is_primary, ist_now, ist_now, notes, tags,
                 contact_email, scan_frequency, active_scan_enabled]
            )
            return {
                'domain': domain,
                'organization': self.organization,  # From instance
                'domain_type': domain_type,
                'is_primary': is_primary,
                'created_at': ist_now,
                'notes': notes,
                'tags': tags,
                'contact_email': contact_email,
                'scan_frequency': scan_frequency,
                'active_scan_enabled': active_scan_enabled
            }

        return await asyncio.get_event_loop().run_in_executor(None, _add_domain)
    
    async def get_domains(self, limit: int = 20, offset: int = 0,
                         domain_type: Optional[str] = None,
                         primary_only: bool = False) -> Dict[str, Any]:
        """
        Get paginated list of domains.

        Args:
            limit: Maximum number of domains to return
            offset: Number of domains to skip
            domain_type: Filter by domain type ('apex' or 'subdomain')
            primary_only: Only return primary domains
        """
        def _get_domains():
            # Build WHERE clause based on filters
            where_conditions = []
            params = []

            if domain_type:
                where_conditions.append("domain_type = ?")
                params.append(domain_type)

            if primary_only:
                where_conditions.append("is_primary = TRUE")

            where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""

            # Query domains with all metadata
            domains_query = f"""
                SELECT
                    domain,
                    domain_type,
                    is_primary,
                    created_at,
                    updated_at,
                    last_scanned_at,
                    scan_count,
                    notes,
                    tags,
                    contact_email,
                    scan_frequency,
                    active_scan_enabled
                FROM domains
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """

            params.extend([limit, offset])
            results = self.connection.execute(domains_query, params).fetchall()

            # Get total count with same filters
            count_query = f"SELECT COUNT(*) FROM domains {where_clause}"
            count_params = params[:-2] if where_conditions else []
            total_count = self.connection.execute(count_query, count_params).fetchone()[0]

            domains = []
            for row in results:
                domain_name = row[0]

                # Get findings count separately
                findings_count = self.connection.execute(
                    "SELECT COUNT(*) FROM security_alerts WHERE domain = ?",
                    [domain_name]
                ).fetchone()[0]

                # Convert timestamps to IST
                created_at_ist = to_ist(row[3]) if row[3] else None
                updated_at_ist = to_ist(row[4]) if row[4] else None
                last_scanned_at_ist = to_ist(row[5]) if row[5] else None

                domains.append({
                    'domain': domain_name,
                    'domain_type': row[1],
                    'is_primary': row[2],
                    'created_at': created_at_ist,
                    'updated_at': updated_at_ist,
                    'last_scanned_at': last_scanned_at_ist,
                    'scan_count': row[6],
                    'notes': row[7],
                    'tags': row[8],
                    'contact_email': row[9],
                    'scan_frequency': row[10],
                    'active_scan_enabled': row[11],
                    'findings_count': findings_count
                })

            return {
                'domains': domains,
                'total_count': total_count,
                'has_more': offset + len(domains) < total_count
            }

        return await asyncio.get_event_loop().run_in_executor(None, _get_domains)
    
    async def delete_domain(self, domain: str) -> bool:
        """Remove a domain from tracking."""
        def _delete_domain():
            # Delete related alerts first
            self.connection.execute("DELETE FROM security_alerts WHERE domain = ?", [domain])
            # Delete the domain
            result = self.connection.execute("DELETE FROM domains WHERE domain = ?", [domain])
            return result.rowcount > 0

        return await asyncio.get_event_loop().run_in_executor(None, _delete_domain)

    async def get_deletion_preview(self, organization: Optional[str] = None, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive preview of what will be deleted across ALL tables.

        Shows counts for:
        - scan_sessions
        - security_alerts
        - All tool-specific results tables
        - All tool-specific history tables
        """
        def _get_preview():
            if organization:
                # Get domains for this organization
                domains_result = self.connection.execute(
                    "SELECT domain FROM domains WHERE organization = ?",
                    [organization]
                ).fetchall()
                domains = [d[0] for d in domains_result]
            elif domain:
                domains = [domain]
            else:
                return {'error': 'Must specify organization or domain'}

            if not domains:
                return {
                    'domains': [],
                    'total_domains': 0,
                    'totals': {}
                }

            # Initialize totals
            totals = {
                'scan_sessions': 0,
                'security_alerts': 0,
                'subfinder_results': 0,
                'amass_results': 0,
                'nmap_results': 0,
                'naabu_results': 0,
                'subfinder_history': 0,
                'amass_history': 0,
                'nmap_history': 0,
                'naabu_history': 0,
                'subdomain_history': 0,
                'domains': 0
            }

            # Count for each domain
            preview_data = []

            for dom in domains:
                subdomain_pattern = f'%.{dom}'
                counts = {}

                # Count scan_sessions
                counts['scan_sessions'] = self.connection.execute(
                    "SELECT COUNT(*) FROM scan_sessions WHERE domains_scanned[1] = ?",
                    [dom]
                ).fetchone()[0]

                # Count security_alerts
                counts['security_alerts'] = self.connection.execute(
                    "SELECT COUNT(*) FROM security_alerts WHERE domain = ? OR domain LIKE ?",
                    [dom, subdomain_pattern]
                ).fetchone()[0]

                # Count subfinder_results
                counts['subfinder_results'] = self.connection.execute(
                    "SELECT COUNT(*) FROM subfinder_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                    [dom, dom, subdomain_pattern]
                ).fetchone()[0]

                # Count amass_results
                counts['amass_results'] = self.connection.execute(
                    "SELECT COUNT(*) FROM amass_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                    [dom, dom, subdomain_pattern]
                ).fetchone()[0]

                # Count nmap_results
                counts['nmap_results'] = self.connection.execute(
                    "SELECT COUNT(*) FROM nmap_results WHERE host = ? OR host LIKE ?",
                    [dom, subdomain_pattern]
                ).fetchone()[0]

                # Count naabu_results
                counts['naabu_results'] = self.connection.execute(
                    "SELECT COUNT(*) FROM naabu_results WHERE host = ? OR host LIKE ?",
                    [dom, subdomain_pattern]
                ).fetchone()[0]

                # Count tool-specific history tables
                counts['subfinder_history'] = self.connection.execute(
                    "SELECT COUNT(*) FROM subfinder_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                    [dom, dom, subdomain_pattern]
                ).fetchone()[0]

                counts['amass_history'] = self.connection.execute(
                    "SELECT COUNT(*) FROM amass_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                    [dom, dom, subdomain_pattern]
                ).fetchone()[0]

                counts['nmap_history'] = self.connection.execute(
                    "SELECT COUNT(*) FROM nmap_history WHERE host = ? OR host LIKE ?",
                    [dom, subdomain_pattern]
                ).fetchone()[0]

                counts['naabu_history'] = self.connection.execute(
                    "SELECT COUNT(*) FROM naabu_history WHERE host = ? OR host LIKE ?",
                    [dom, subdomain_pattern]
                ).fetchone()[0]

                counts['subdomain_history'] = self.connection.execute(
                    "SELECT COUNT(*) FROM subdomain_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                    [dom, dom, subdomain_pattern]
                ).fetchone()[0]

                counts['domains'] = 1  # The domain itself

                # Add to totals
                for key, value in counts.items():
                    totals[key] += value

                preview_data.append({
                    'domain': dom,
                    **counts
                })

            # Calculate grand total
            totals['total_records'] = sum(totals.values())

            return {
                'domains': preview_data,
                'total_domains': len(domains),
                'totals': totals
            }

        return await asyncio.get_event_loop().run_in_executor(None, _get_preview)

    async def delete_organization(self, organization: str) -> Dict[str, int]:
        """Delete all data for an organization."""
        def _delete_org():
            # Get domains for this organization
            domains_result = self.connection.execute(
                "SELECT domain FROM domains WHERE organization = ?",
                [organization]
            ).fetchall()
            domains = [d[0] for d in domains_result]

            if not domains:
                return {'domains': 0, 'alerts': 0, 'scans': 0}

            # Delete security alerts
            alert_count = 0
            scan_count = 0

            for domain in domains:
                # Count before delete
                alert_count_result = self.connection.execute(
                    "SELECT COUNT(*) FROM security_alerts WHERE domain = ?",
                    [domain]
                ).fetchone()
                alert_count += alert_count_result[0] if alert_count_result else 0

                scan_count_result = self.connection.execute(
                    "SELECT COUNT(*) FROM scan_sessions WHERE domains_scanned[1] = ?",
                    [domain]
                ).fetchone()
                scan_count += scan_count_result[0] if scan_count_result else 0

                # Perform deletions
                self.connection.execute(
                    "DELETE FROM security_alerts WHERE domain = ?",
                    [domain]
                )
                self.connection.execute(
                    "DELETE FROM scan_sessions WHERE domains_scanned[1] = ?",
                    [domain]
                )

            # Delete domains (count before delete)
            domain_count_result = self.connection.execute(
                "SELECT COUNT(*) FROM domains WHERE organization = ?",
                [organization]
            ).fetchone()
            domain_count = domain_count_result[0] if domain_count_result else 0

            self.connection.execute(
                "DELETE FROM domains WHERE organization = ?",
                [organization]
            )

            return {
                'domains': domain_count,
                'alerts': alert_count,
                'scans': scan_count
            }

        return await asyncio.get_event_loop().run_in_executor(None, _delete_org)

    async def delete_domain_with_data(self, domain: str) -> Dict[str, int]:
        """
        Delete a domain and ALL its associated data across all tables.

        Performs cascade deletion across:
        - scan_sessions
        - security_alerts
        - Tool-specific results tables (subfinder, amass, nmap, naabu)
        - Tool-specific history tables
        - subdomain_history (legacy)
        - domains table
        """
        def _delete_domain_data():
            # Pattern for matching domain and subdomains
            subdomain_pattern = f'%.{domain}'

            # Count before delete
            counts = {}

            # 1. Count scan_sessions
            counts['scan_sessions'] = self.connection.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE domains_scanned[1] = ?",
                [domain]
            ).fetchone()[0]

            # 2. Count security_alerts (includes apex + subdomains)
            counts['security_alerts'] = self.connection.execute(
                "SELECT COUNT(*) FROM security_alerts WHERE domain = ? OR domain LIKE ?",
                [domain, subdomain_pattern]
            ).fetchone()[0]

            # 3. Count subfinder_results
            counts['subfinder_results'] = self.connection.execute(
                "SELECT COUNT(*) FROM subfinder_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            ).fetchone()[0]

            # 4. Count amass_results
            counts['amass_results'] = self.connection.execute(
                "SELECT COUNT(*) FROM amass_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            ).fetchone()[0]

            # 5. Count nmap_results
            counts['nmap_results'] = self.connection.execute(
                "SELECT COUNT(*) FROM nmap_results WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            ).fetchone()[0]

            # 6. Count naabu_results
            counts['naabu_results'] = self.connection.execute(
                "SELECT COUNT(*) FROM naabu_results WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            ).fetchone()[0]

            # 7. Count subfinder_history
            counts['subfinder_history'] = self.connection.execute(
                "SELECT COUNT(*) FROM subfinder_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            ).fetchone()[0]

            # 8. Count amass_history
            counts['amass_history'] = self.connection.execute(
                "SELECT COUNT(*) FROM amass_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            ).fetchone()[0]

            # 9. Count nmap_history
            counts['nmap_history'] = self.connection.execute(
                "SELECT COUNT(*) FROM nmap_history WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            ).fetchone()[0]

            # 10. Count naabu_history
            counts['naabu_history'] = self.connection.execute(
                "SELECT COUNT(*) FROM naabu_history WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            ).fetchone()[0]

            # 11. Count subdomain_history (legacy table)
            counts['subdomain_history'] = self.connection.execute(
                "SELECT COUNT(*) FROM subdomain_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            ).fetchone()[0]

            # 12. Count domains
            counts['domains'] = self.connection.execute(
                "SELECT COUNT(*) FROM domains WHERE domain = ?",
                [domain]
            ).fetchone()[0]

            # PERFORM CASCADE DELETIONS

            # Delete from scan_sessions
            self.connection.execute(
                "DELETE FROM scan_sessions WHERE domains_scanned[1] = ?",
                [domain]
            )

            # Delete from security_alerts
            self.connection.execute(
                "DELETE FROM security_alerts WHERE domain = ? OR domain LIKE ?",
                [domain, subdomain_pattern]
            )

            # Delete from subfinder_results
            self.connection.execute(
                "DELETE FROM subfinder_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            )

            # Delete from amass_results
            self.connection.execute(
                "DELETE FROM amass_results WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            )

            # Delete from nmap_results
            self.connection.execute(
                "DELETE FROM nmap_results WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            )

            # Delete from naabu_results
            self.connection.execute(
                "DELETE FROM naabu_results WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            )

            # Delete from subfinder_history
            self.connection.execute(
                "DELETE FROM subfinder_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            )

            # Delete from amass_history
            self.connection.execute(
                "DELETE FROM amass_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            )

            # Delete from nmap_history
            self.connection.execute(
                "DELETE FROM nmap_history WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            )

            # Delete from naabu_history
            self.connection.execute(
                "DELETE FROM naabu_history WHERE host = ? OR host LIKE ?",
                [domain, subdomain_pattern]
            )

            # Delete from subdomain_history (legacy)
            self.connection.execute(
                "DELETE FROM subdomain_history WHERE apex_domain = ? OR subdomain = ? OR subdomain LIKE ?",
                [domain, domain, subdomain_pattern]
            )

            # Delete from domains table
            self.connection.execute(
                "DELETE FROM domains WHERE domain = ?",
                [domain]
            )

            # Calculate totals
            total_deleted = sum(counts.values())

            return {
                **counts,
                'total_records_deleted': total_deleted
            }

        return await asyncio.get_event_loop().run_in_executor(None, _delete_domain_data)
    
    async def domain_exists(self, domain: str) -> bool:
        """Check if domain exists in database."""
        def _domain_exists():
            result = self.connection.execute(
                "SELECT COUNT(*) FROM domains WHERE domain = ?", [domain]
            ).fetchone()
            return result[0] > 0

        return await asyncio.get_event_loop().run_in_executor(None, _domain_exists)

    async def update_domain(self, domain: str, **kwargs) -> Dict[str, Any]:
        """
        Update domain metadata.

        Args:
            domain: Domain name
            **kwargs: Fields to update (notes, tags, contact_email, scan_frequency, etc.)
        """
        def _update_domain():
            # Build UPDATE query dynamically based on provided fields
            update_fields = []
            params = []

            allowed_fields = ['is_primary', 'domain_type', 'notes', 'tags',
                            'contact_email', 'scan_frequency', 'active_scan_enabled']

            for field, value in kwargs.items():
                if field in allowed_fields:
                    update_fields.append(f"{field} = ?")
                    params.append(value)

            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}

            # Always update updated_at
            update_fields.append("updated_at = ?")
            params.append(get_ist_now())

            # Add domain to params
            params.append(domain)

            query = f"UPDATE domains SET {', '.join(update_fields)} WHERE domain = ?"
            self.connection.execute(query, params)

            return {'success': True, 'message': f'Domain {domain} updated'}

        return await asyncio.get_event_loop().run_in_executor(None, _update_domain)

    # Subdomain History Management
    async def add_subdomain_to_history(self, apex_domain: str, subdomain: str,
                                      scan_id: str, status: str,
                                      tool_source: Optional[str] = None,
                                      metadata: Optional[str] = None) -> Dict[str, Any]:
        """
        Add or update subdomain in history.

        Args:
            apex_domain: The apex domain this subdomain belongs to
            subdomain: The full subdomain (e.g., api.example.com)
            scan_id: Scan ID that discovered this subdomain
            status: Status ('new', 'existing', 'removed')
            tool_source: Tool that found this subdomain
            metadata: Optional metadata in JSON format
        """
        def _add_subdomain():
            ist_now = get_ist_now()

            # Check if subdomain already exists in history
            existing = self.connection.execute(
                "SELECT id, first_seen FROM subdomain_history WHERE subdomain = ? ORDER BY last_seen DESC LIMIT 1",
                [subdomain]
            ).fetchone()

            if existing:
                # Update existing record
                history_id = existing[0]
                first_seen = existing[1]

                self.connection.execute(
                    """UPDATE subdomain_history
                       SET last_seen = ?, status = ?, scan_id = ?, tool_source = ?, metadata = ?
                       WHERE id = ?""",
                    [ist_now, status, scan_id, tool_source, metadata, history_id]
                )
                return {
                    'id': history_id,
                    'subdomain': subdomain,
                    'status': status,
                    'first_seen': first_seen,
                    'last_seen': ist_now,
                    'action': 'updated'
                }
            else:
                # Insert new record
                history_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO subdomain_history
                       (id, apex_domain, subdomain, scan_id, status, first_seen, last_seen, tool_source, metadata)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [history_id, apex_domain, subdomain, scan_id, status, ist_now, ist_now, tool_source, metadata]
                )
                return {
                    'id': history_id,
                    'subdomain': subdomain,
                    'status': status,
                    'first_seen': ist_now,
                    'last_seen': ist_now,
                    'action': 'created'
                }

        return await asyncio.get_event_loop().run_in_executor(None, _add_subdomain)

    async def get_subdomain_history(self, apex_domain: str,
                                   limit: int = 100,
                                   offset: int = 0) -> Dict[str, Any]:
        """
        Get subdomain history for an apex domain.

        Args:
            apex_domain: Apex domain to get history for
            limit: Maximum number of records to return
            offset: Number of records to skip
        """
        def _get_history():
            query = """
                SELECT id, apex_domain, subdomain, scan_id, status, first_seen, last_seen, tool_source, metadata
                FROM subdomain_history
                WHERE apex_domain = ?
                ORDER BY last_seen DESC
                LIMIT ? OFFSET ?
            """

            results = self.connection.execute(query, [apex_domain, limit, offset]).fetchall()

            # Get total count
            total_count = self.connection.execute(
                "SELECT COUNT(*) FROM subdomain_history WHERE apex_domain = ?",
                [apex_domain]
            ).fetchone()[0]

            history = []
            for row in results:
                first_seen_ist = to_ist(row[5]) if row[5] else None
                last_seen_ist = to_ist(row[6]) if row[6] else None

                history.append({
                    'id': row[0],
                    'apex_domain': row[1],
                    'subdomain': row[2],
                    'scan_id': row[3],
                    'status': row[4],
                    'first_seen': first_seen_ist,
                    'last_seen': last_seen_ist,
                    'tool_source': row[7],
                    'metadata': row[8]
                })

            return {
                'history': history,
                'total_count': total_count,
                'has_more': offset + len(history) < total_count
            }

        return await asyncio.get_event_loop().run_in_executor(None, _get_history)

    async def get_subdomain_changes(self, apex_domain: str, scan_id: str) -> Dict[str, Any]:
        """
        Get subdomain changes detected in a specific scan.

        Args:
            apex_domain: Apex domain
            scan_id: Scan ID to get changes for
        """
        def _get_changes():
            query = """
                SELECT subdomain, status, tool_source, first_seen, last_seen
                FROM subdomain_history
                WHERE apex_domain = ? AND scan_id = ?
                ORDER BY status, subdomain
            """

            results = self.connection.execute(query, [apex_domain, scan_id]).fetchall()

            new_subdomains = []
            existing_subdomains = []
            removed_subdomains = []

            for row in results:
                subdomain_data = {
                    'subdomain': row[0],
                    'tool_source': row[2],
                    'first_seen': to_ist(row[3]) if row[3] else None,
                    'last_seen': to_ist(row[4]) if row[4] else None
                }

                if row[1] == 'new':
                    new_subdomains.append(subdomain_data)
                elif row[1] == 'existing':
                    existing_subdomains.append(subdomain_data)
                elif row[1] == 'removed':
                    removed_subdomains.append(subdomain_data)

            return {
                'apex_domain': apex_domain,
                'scan_id': scan_id,
                'new': new_subdomains,
                'existing': existing_subdomains,
                'removed': removed_subdomains,
                'total_new': len(new_subdomains),
                'total_existing': len(existing_subdomains),
                'total_removed': len(removed_subdomains)
            }

        return await asyncio.get_event_loop().run_in_executor(None, _get_changes)

    # Scan Management
    async def create_scan_session(self, scan_type: str, domains: List[str], tool_name: Optional[str] = None) -> str:
        """
        Create a new scan session and return scan_id.

        Args:
            scan_type: Type of scan (e.g., 'passive_subdomain_enum', 'active_port_scan')
            domains: List of domains to scan
            tool_name: Name of tool used (e.g., 'subfinder', 'amass', 'nmap', 'naabu')
        """
        def _create_scan():
            ist_now = get_ist_now()
            scan_id = str(uuid.uuid4())
            self.connection.execute(
                "INSERT INTO scan_sessions (scan_id, scan_type, tool_name, domains_scanned, start_time, status) VALUES (?, ?, ?, ?, ?, 'queued')",
                [scan_id, scan_type, tool_name, domains, ist_now]
            )
            return scan_id

        return await asyncio.get_event_loop().run_in_executor(None, _create_scan)
    
    async def update_scan_status(self, scan_id: str, status: str, 
                                end_time: Optional[datetime] = None,
                                findings_count: Optional[int] = None) -> None:
        """Update scan session status."""
        def _update_scan():
            params = [status]
            query_parts = ["status = ?"]
            
            if end_time:
                query_parts.append("end_time = ?")
                params.append(end_time)
            
            if findings_count is not None:
                query_parts.append("findings_count = ?")
                params.append(findings_count)
            
            params.append(scan_id)
            query = f"UPDATE scan_sessions SET {', '.join(query_parts)} WHERE scan_id = ?"
            
            self.connection.execute(query, params)
        
        await asyncio.get_event_loop().run_in_executor(None, _update_scan)
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session information."""
        def _get_scan():
            result = self.connection.execute(
                "SELECT scan_id, scan_type, tool_name, domains_scanned, start_time, end_time, status, findings_count FROM scan_sessions WHERE scan_id = ?",
                [scan_id]
            ).fetchone()

            if not result:
                return None

            # Convert timestamps to IST
            start_time_ist = to_ist(result[4]) if result[4] else None
            end_time_ist = to_ist(result[5]) if result[5] else None

            return {
                'scan_id': result[0],
                'scan_type': result[1],
                'tool_name': result[2],
                'domains': result[3],
                'start_time': start_time_ist,
                'end_time': end_time_ist,
                'status': result[6],
                'findings_count': result[7]
            }
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_scan)
    
    # Security Alerts
    async def store_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Store security alerts from scan results."""
        def _store_alerts():
            for alert in alerts:
                alert_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO security_alerts 
                       (id, domain, scan_id, vulnerability_type, severity, description, remediation, tool_source, discovered_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        alert_id,
                        alert.get('domain', ''),
                        alert.get('scan_id', ''),
                        alert.get('type', alert.get('vulnerability_type', 'unknown')),
                        alert.get('severity', 'medium'),
                        alert.get('description', alert.get('message', '')),
                        alert.get('remediation', ''),
                        alert.get('tool_source', alert.get('source', 'unknown')),
                        alert.get('discovered_at', get_ist_now())
                    ]
                )
        
        await asyncio.get_event_loop().run_in_executor(None, _store_alerts)

    # Tool-specific result storage
    async def store_subfinder_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store subfinder scan results.

        Args:
            results: List of subfinder findings with keys:
                - scan_id: Scan session ID
                - apex_domain: Apex domain
                - subdomain: Discovered subdomain
                - source: Subfinder source (optional)
                - raw_json: Raw JSON output (optional)
        """
        def _store_subfinder():
            for result in results:
                result_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO subfinder_results
                       (id, scan_id, apex_domain, subdomain, source, discovered_at, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    [
                        result_id,
                        result.get('scan_id'),
                        result.get('apex_domain'),
                        result.get('subdomain'),
                        result.get('source'),
                        result.get('discovered_at', get_ist_now()),
                        result.get('raw_json')
                    ]
                )

        await asyncio.get_event_loop().run_in_executor(None, _store_subfinder)

    async def store_amass_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store amass scan results.

        Args:
            results: List of amass findings with keys:
                - scan_id, apex_domain, subdomain, ip_address, cidr, asn, sources, raw_json
        """
        def _store_amass():
            for result in results:
                result_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO amass_results
                       (id, scan_id, apex_domain, subdomain, ip_address, cidr, asn, sources, discovered_at, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        result_id,
                        result.get('scan_id'),
                        result.get('apex_domain'),
                        result.get('subdomain'),
                        result.get('ip_address'),
                        result.get('cidr'),
                        result.get('asn'),
                        result.get('sources'),
                        result.get('discovered_at', get_ist_now()),
                        result.get('raw_json')
                    ]
                )

        await asyncio.get_event_loop().run_in_executor(None, _store_amass)

    async def store_nmap_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store nmap scan results.

        Args:
            results: List of nmap findings with keys:
                - scan_id, host, port, protocol, state, service, service_version,
                  os_info, cpe, scripts_output, raw_xml
        """
        def _store_nmap():
            for result in results:
                result_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO nmap_results
                       (id, scan_id, host, port, protocol, state, service, service_version,
                        os_info, cpe, scripts_output, discovered_at, raw_xml)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        result_id,
                        result.get('scan_id'),
                        result.get('host'),
                        result.get('port'),
                        result.get('protocol'),
                        result.get('state'),
                        result.get('service'),
                        result.get('service_version'),
                        result.get('os_info'),
                        result.get('cpe'),
                        result.get('scripts_output'),
                        result.get('discovered_at', get_ist_now()),
                        result.get('raw_xml')
                    ]
                )

        await asyncio.get_event_loop().run_in_executor(None, _store_nmap)

    async def store_naabu_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store naabu scan results.

        Args:
            results: List of naabu findings with keys:
                - scan_id, host, port, protocol, ip, raw_json
        """
        def _store_naabu():
            for result in results:
                result_id = str(uuid.uuid4())
                self.connection.execute(
                    """INSERT INTO naabu_results
                       (id, scan_id, host, port, protocol, ip, discovered_at, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        result_id,
                        result.get('scan_id'),
                        result.get('host'),
                        result.get('port'),
                        result.get('protocol'),
                        result.get('ip'),
                        result.get('discovered_at', get_ist_now()),
                        result.get('raw_json')
                    ]
                )

        await asyncio.get_event_loop().run_in_executor(None, _store_naabu)

    async def get_alerts(self, limit: int = 50, offset: int = 0, 
                        severity_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get paginated security alerts with optional severity filtering."""
        def _get_alerts():
            # Build query with optional severity filter
            where_clause = ""
            params = []
            
            if severity_filter:
                placeholders = ','.join(['?' for _ in severity_filter])
                where_clause = f"WHERE severity IN ({placeholders})"
                params.extend(severity_filter)
            
            # Get alerts
            alerts_query = f"""
                SELECT id, domain, vulnerability_type, severity, description, remediation, tool_source, discovered_at
                FROM security_alerts 
                {where_clause}
                ORDER BY discovered_at DESC, severity DESC
                LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])
            
            results = self.connection.execute(alerts_query, params).fetchall()
            
            # Get total count
            count_query = f"SELECT COUNT(*) FROM security_alerts {where_clause}"
            count_params = params[:-2] if severity_filter else []  # Remove limit and offset
            total_count = self.connection.execute(count_query, count_params).fetchone()[0]
            
            # Get severity breakdown
            breakdown_query = """
                SELECT severity, COUNT(*) 
                FROM security_alerts 
                GROUP BY severity
            """
            breakdown_results = self.connection.execute(breakdown_query).fetchall()
            severity_breakdown = {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0
            }
            for severity, count in breakdown_results:
                severity_breakdown[severity] = count
            
            alerts = []
            for row in results:
                # Convert discovered_at timestamp to IST
                discovered_at_ist = to_ist(row[7]) if row[7] else None
                
                alerts.append({
                    'id': row[0],
                    'domain': row[1],
                    'vulnerability_type': row[2],
                    'severity': row[3],
                    'description': row[4],
                    'remediation': row[5],
                    'tool_source': row[6],
                    'discovered_at': discovered_at_ist
                })
            
            return {
                'alerts': alerts,
                'severity_breakdown': severity_breakdown,
                'total_count': total_count,
                'has_more': offset + len(alerts) < total_count
            }
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_alerts)
    
    # System Metrics
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics and performance data."""
        def _get_metrics():
            # Get basic counts
            domain_count = self.connection.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
            active_scans = self.connection.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE status IN ('queued', 'running')"
            ).fetchone()[0]
            
            # Get database size (approximate)
            try:
                db_size_bytes = Path(self.db_path).stat().st_size if Path(self.db_path).exists() else 0
                db_size_mb = db_size_bytes / (1024 * 1024)
            except:
                db_size_mb = 0.0
            
            # Get 24h stats
            scans_24h = self.connection.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE start_time > datetime('now', '-1 day')"
            ).fetchone()[0]
            
            successful_scans = self.connection.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE status = 'completed' AND start_time > datetime('now', '-1 day')"
            ).fetchone()[0]
            
            failed_scans = self.connection.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE status = 'failed' AND start_time > datetime('now', '-1 day')"
            ).fetchone()[0]
            
            alerts_24h = self.connection.execute(
                "SELECT COUNT(*) FROM security_alerts WHERE discovered_at > datetime('now', '-1 day')"
            ).fetchone()[0]
            
            return {
                'total_domains': domain_count,
                'active_scans': active_scans,
                'database_size_mb': round(db_size_mb, 2),
                'successful_scans_24h': successful_scans,
                'failed_scans_24h': failed_scans,
                'alerts_generated_24h': alerts_24h
            }
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_metrics)
    
    async def get_health_status(self) -> Dict[str, bool]:
        """Get database health status."""
        def _get_health():
            try:
                # Test basic database connectivity
                self.connection.execute("SELECT 1").fetchone()
                database = True
            except:
                database = False
            
            # Check if we can write to the database
            try:
                self.connection.execute("SELECT COUNT(*) FROM domains").fetchone()
                memory_usage = True  # If we can query, memory is OK
            except:
                memory_usage = False
            
            return {
                'database': database,
                'memory_usage': memory_usage,
                'security_tools': True  # Assume tools are available
            }
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_health)