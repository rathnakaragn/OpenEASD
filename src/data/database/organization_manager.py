"""
Organization Manager for Multi-Org Architecture.

Manages organization registry and routes database operations to
organization-specific DuckDB files.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

import asyncio
import duckdb
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

from src.utils.timezone import get_ist_now


class OrganizationManager:
    """
    Manage organization registry and database routing.

    Each organization gets its own DuckDB file for complete isolation.
    Registry database tracks all organizations and their metadata.
    """

    def __init__(self, registry_path: str = 'data/registry.db', data_dir: str = 'data/organizations'):
        """
        Initialize Organization Manager.

        Args:
            registry_path: Path to organization registry database
            data_dir: Base directory for organization databases
        """
        self.registry_path = registry_path
        self.data_dir = data_dir
        self.registry_conn = None
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure required directories exist."""
        # Create data directory
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)

        # Create registry directory
        Path(self.registry_path).parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> None:
        """Initialize registry database and create schema."""
        await asyncio.get_event_loop().run_in_executor(None, self._initialize_sync)

    def _initialize_sync(self):
        """Synchronous registry initialization."""
        self.registry_conn = duckdb.connect(self.registry_path)

        # Create organizations table
        self.registry_conn.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                org_id VARCHAR PRIMARY KEY,
                org_name VARCHAR NOT NULL,
                org_slug VARCHAR UNIQUE NOT NULL,
                db_path VARCHAR NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scan_at TIMESTAMP,
                total_domains INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                status VARCHAR DEFAULT 'active'
            )
        """)

        # Create metadata table
        self.registry_conn.execute("""
            CREATE TABLE IF NOT EXISTS org_metadata (
                org_id VARCHAR PRIMARY KEY,
                contact_email VARCHAR,
                contact_name VARCHAR,
                industry VARCHAR,
                tags VARCHAR[],
                notes TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id)
            )
        """)

        # Create indexes
        self.registry_conn.execute("CREATE INDEX IF NOT EXISTS idx_org_slug ON organizations(org_slug)")
        self.registry_conn.execute("CREATE INDEX IF NOT EXISTS idx_org_status ON organizations(status)")

    async def close(self) -> None:
        """Close registry database connection."""
        if self.registry_conn:
            await asyncio.get_event_loop().run_in_executor(None, self.registry_conn.close)
            self.registry_conn = None

    def _generate_org_slug(self, org_name: str) -> str:
        """
        Generate URL-safe organization slug from name.

        Args:
            org_name: Organization name (e.g., "Tesla Inc.")

        Returns:
            URL-safe slug (e.g., "tesla-inc")
        """
        # Convert to lowercase
        slug = org_name.lower()

        # Replace spaces and special chars with hyphens
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[\s_-]+', '-', slug)
        slug = slug.strip('-')

        return slug

    def _generate_org_id(self, org_slug: str) -> str:
        """Generate unique organization ID."""
        import uuid
        return f"org_{org_slug}_{uuid.uuid4().hex[:8]}"

    async def create_organization(self, org_name: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create new organization with dedicated database.

        Args:
            org_name: Organization name
            metadata: Optional metadata (contact_email, contact_name, industry, etc.)

        Returns:
            Organization details
        """
        def _create_org():
            # Generate slug and ID
            org_slug = self._generate_org_slug(org_name)

            # Check if organization already exists
            existing = self.registry_conn.execute(
                "SELECT org_id, org_name, db_path FROM organizations WHERE org_slug = ?",
                [org_slug]
            ).fetchone()

            if existing:
                return {
                    'org_id': existing[0],
                    'org_name': existing[1],
                    'org_slug': org_slug,
                    'db_path': existing[2],
                    'created': False,
                    'message': 'Organization already exists'
                }

            org_id = self._generate_org_id(org_slug)

            # Create organization directory
            org_dir = Path(self.data_dir) / org_slug
            org_dir.mkdir(parents=True, exist_ok=True)

            # Database path
            db_path = str(org_dir / 'openeasd.db')

            # Create organization database
            org_conn = duckdb.connect(db_path)

            # Initialize organization database schema
            org_conn.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    domain VARCHAR PRIMARY KEY,
                    is_primary BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            org_conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    scan_id VARCHAR PRIMARY KEY,
                    scan_type VARCHAR NOT NULL,
                    domains_scanned VARCHAR[],
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    status VARCHAR DEFAULT 'queued',
                    findings_count INTEGER DEFAULT 0
                )
            """)

            org_conn.execute("""
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

            # Create indexes
            org_conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_domain ON security_alerts(domain)")
            org_conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
            org_conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_sessions(status)")

            org_conn.close()

            # Register organization in registry
            ist_now = get_ist_now()
            self.registry_conn.execute("""
                INSERT INTO organizations (org_id, org_name, org_slug, db_path, created_at, status)
                VALUES (?, ?, ?, ?, ?, 'active')
            """, [org_id, org_name, org_slug, db_path, ist_now])

            # Add metadata if provided
            if metadata:
                self.registry_conn.execute("""
                    INSERT INTO org_metadata (org_id, contact_email, contact_name, industry, tags, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, [
                    org_id,
                    metadata.get('contact_email'),
                    metadata.get('contact_name'),
                    metadata.get('industry'),
                    metadata.get('tags'),
                    metadata.get('notes')
                ])

            return {
                'org_id': org_id,
                'org_name': org_name,
                'org_slug': org_slug,
                'db_path': db_path,
                'created': True,
                'message': f'Organization {org_name} created successfully'
            }

        return await asyncio.get_event_loop().run_in_executor(None, _create_org)

    async def organization_exists(self, org_name: str) -> bool:
        """Check if organization exists."""
        def _check_exists():
            org_slug = self._generate_org_slug(org_name)
            result = self.registry_conn.execute(
                "SELECT COUNT(*) FROM organizations WHERE org_slug = ?",
                [org_slug]
            ).fetchone()
            return result[0] > 0

        return await asyncio.get_event_loop().run_in_executor(None, _check_exists)

    async def get_organization_db_path(self, org_name: str) -> Optional[str]:
        """
        Get database path for organization.

        Args:
            org_name: Organization name

        Returns:
            Database path or None if not found
        """
        def _get_path():
            org_slug = self._generate_org_slug(org_name)
            result = self.registry_conn.execute(
                "SELECT db_path FROM organizations WHERE org_slug = ?",
                [org_slug]
            ).fetchone()

            return result[0] if result else None

        return await asyncio.get_event_loop().run_in_executor(None, _get_path)

    async def get_organization_info(self, org_name: str) -> Optional[Dict[str, Any]]:
        """Get full organization information."""
        def _get_info():
            org_slug = self._generate_org_slug(org_name)
            result = self.registry_conn.execute("""
                SELECT org_id, org_name, org_slug, db_path, created_at,
                       last_scan_at, total_domains, total_scans, status
                FROM organizations
                WHERE org_slug = ?
            """, [org_slug]).fetchone()

            if not result:
                return None

            return {
                'org_id': result[0],
                'org_name': result[1],
                'org_slug': result[2],
                'db_path': result[3],
                'created_at': result[4],
                'last_scan_at': result[5],
                'total_domains': result[6],
                'total_scans': result[7],
                'status': result[8]
            }

        return await asyncio.get_event_loop().run_in_executor(None, _get_info)

    async def list_organizations(self, status: str = 'active') -> List[Dict[str, Any]]:
        """List all organizations."""
        def _list_orgs():
            query = "SELECT org_id, org_name, org_slug, db_path, created_at, last_scan_at, total_domains, total_scans, status FROM organizations"

            if status:
                query += " WHERE status = ?"
                result = self.registry_conn.execute(query, [status]).fetchall()
            else:
                result = self.registry_conn.execute(query).fetchall()

            orgs = []
            for row in result:
                orgs.append({
                    'org_id': row[0],
                    'org_name': row[1],
                    'org_slug': row[2],
                    'db_path': row[3],
                    'created_at': row[4],
                    'last_scan_at': row[5],
                    'total_domains': row[6],
                    'total_scans': row[7],
                    'status': row[8]
                })

            return orgs

        return await asyncio.get_event_loop().run_in_executor(None, _list_orgs)

    async def update_organization_stats(self, org_name: str, total_domains: int, total_scans: int) -> None:
        """Update organization statistics."""
        def _update_stats():
            org_slug = self._generate_org_slug(org_name)
            ist_now = get_ist_now()

            self.registry_conn.execute("""
                UPDATE organizations
                SET total_domains = ?, total_scans = ?, last_scan_at = ?
                WHERE org_slug = ?
            """, [total_domains, total_scans, ist_now, org_slug])

        await asyncio.get_event_loop().run_in_executor(None, _update_stats)

    async def delete_organization(self, org_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Delete organization and its database.

        Args:
            org_name: Organization name
            force: Skip confirmation

        Returns:
            Deletion result
        """
        def _delete_org():
            org_slug = self._generate_org_slug(org_name)

            # Get organization info
            result = self.registry_conn.execute(
                "SELECT org_id, db_path FROM organizations WHERE org_slug = ?",
                [org_slug]
            ).fetchone()

            if not result:
                return {
                    'success': False,
                    'message': f'Organization {org_name} not found'
                }

            org_id, db_path = result

            # Delete organization database file and directory
            db_file = Path(db_path)
            if db_file.exists():
                db_file.unlink()

            # Delete organization directory
            org_dir = db_file.parent
            if org_dir.exists() and org_dir.is_dir():
                shutil.rmtree(org_dir)

            # Delete from metadata
            self.registry_conn.execute(
                "DELETE FROM org_metadata WHERE org_id = ?",
                [org_id]
            )

            # Delete from registry
            self.registry_conn.execute(
                "DELETE FROM organizations WHERE org_id = ?",
                [org_id]
            )

            return {
                'success': True,
                'message': f'Organization {org_name} deleted successfully',
                'org_id': org_id,
                'db_path': db_path
            }

        return await asyncio.get_event_loop().run_in_executor(None, _delete_org)

    async def find_org_for_domain(self, domain: str) -> Optional[str]:
        """
        Find which organization owns a domain.

        Args:
            domain: Domain name

        Returns:
            Organization name or None
        """
        def _find_org():
            # Get all organizations
            orgs = self.registry_conn.execute(
                "SELECT org_name, db_path FROM organizations WHERE status = 'active'"
            ).fetchall()

            # Check each org database
            for org_name, db_path in orgs:
                org_conn = duckdb.connect(db_path, read_only=True)
                result = org_conn.execute(
                    "SELECT COUNT(*) FROM domains WHERE domain = ?",
                    [domain]
                ).fetchone()
                org_conn.close()

                if result[0] > 0:
                    return org_name

            return None

        return await asyncio.get_event_loop().run_in_executor(None, _find_org)
