"""
SQLModel Database Manager for OpenEASD.

Implements DatabaseManager interface using SQLModel with SQLite backend.
Provides complete CRUD operations for domains, scans, alerts, subdomains, and tool results.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

from sqlmodel import SQLModel, Session, create_engine, select, func, and_, delete

from src.core.interfaces.database import DatabaseManager
from src.data.models.domain import Domain
from src.data.models.scan import ScanSession
from src.data.models.subdomain import SubdomainHistory
from src.data.models.tool_results import (
    SubfinderResult,
    AmassResult,
    NmapResult,
    NaabuResult
)
from src.data.models.api_key import APIKey
from src.data.models.audit_log import AuditLog
# Import finding models from data layer (proper layering)
from src.data.models.finding import (
    Finding,
    Vulnerability,
    CVEMapping,
    FindingGroup
)
from src.utils.timezone import get_ist_now, to_ist
from src.utils.config import Config


class SQLModelManager(DatabaseManager):
    """SQLModel implementation of DatabaseManager using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize SQLModel database manager.

        Args:
            db_path: Path to SQLite database file (default: from config or data/openeasd.sqlite)
        """
        if db_path is None:
            config = Config()
            db_path = config.get('database.database_path', 'data/openeasd.sqlite')

        # Create parent directory if needed
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Create SQLite engine
        self.db_url = f"sqlite:///{db_path}"
        self.engine = create_engine(
            self.db_url,
            echo=False,
            connect_args={"check_same_thread": False}
        )
        self.db_path = db_path

    def initialize(self) -> None:
        """Initialize database and create all tables."""
        SQLModel.metadata.create_all(self.engine)

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self, 'engine') and self.engine:
            self.engine.dispose()

    # ============================================================================
    # Domain Management
    # ============================================================================

    def add_domain(
        self,
        domain: str,
        is_primary: bool = False,
        contact_email: Optional[str] = None,
        scan_frequency: Optional[str] = None,
        active_scan_enabled: bool = True
    ) -> Domain:
        """
        Add a domain to tracking with optional metadata.

        Args:
            domain: Domain name (e.g., example.com)
            is_primary: Whether this is a primary domain
            contact_email: Optional contact email
            scan_frequency: Optional scan frequency (daily, weekly, monthly)
            active_scan_enabled: Whether active scanning is enabled

        Returns:
            The created Domain object.
        """
        with Session(self.engine) as session:
            now = get_ist_now()

            domain_obj = Domain(
                domain=domain,
                is_primary=is_primary,
                created_at=now,
                updated_at=now,
                last_scanned_at=None,
                scan_count=0,
                contact_email=contact_email,
                scan_frequency=scan_frequency,
                active_scan_enabled=active_scan_enabled
            )

            session.add(domain_obj)
            session.commit()
            session.refresh(domain_obj)

            return domain_obj

    def get_domains(
        self,
        limit: int = 20,
        offset: int = 0,
        primary_only: bool = False,
        domain_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get paginated list of domains with optional filters.

        Args:
            limit: Maximum number of domains to return
            offset: Number of domains to skip
            primary_only: Only return primary domains
            domain_name: Filter by specific domain name

        Returns:
            Dictionary with domains list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Build query
            query = select(Domain)

            # Apply filters
            if domain_name:
                query = query.where(Domain.domain == domain_name)
            if primary_only:
                query = query.where(Domain.is_primary == True)

            # Get total count
            count_query = select(func.count()).select_from(Domain)
            if domain_name:
                count_query = count_query.where(Domain.domain == domain_name)
            if primary_only:
                count_query = count_query.where(Domain.is_primary == True)

            total_count = session.exec(count_query).one()

            # Apply pagination and ordering
            query = query.order_by(Domain.created_at.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            domains = session.exec(query).all()

            return {
                'domains': domains,
                'total_count': total_count,
                'has_more': (offset + len(domains)) < total_count,
                'limit': limit,
                'offset': offset
            }

    def update_domain(self, domain: str, **kwargs) -> Domain:
        """
        Update domain metadata.

        Args:
            domain: Domain name to update
            **kwargs: Fields to update (is_primary, contact_email, scan_frequency, etc.)

        Returns:
            The updated domain object.
        """
        with Session(self.engine) as session:
            domain_obj = session.get(Domain, domain)

            if not domain_obj:
                raise ValueError(f"Domain {domain} not found")

            # Update fields
            for key, value in kwargs.items():
                if hasattr(domain_obj, key):
                    setattr(domain_obj, key, value)

            # Update timestamp
            domain_obj.updated_at = get_ist_now()

            session.add(domain_obj)
            session.commit()
            session.refresh(domain_obj)

            return domain_obj

    def delete_domain(self, domain: str) -> bool:
        """
        Remove a domain from tracking (simple deletion without cascade).

        Args:
            domain: Domain name to delete

        Returns:
            True if deleted successfully, False otherwise
        """
        with Session(self.engine) as session:
            domain_obj = session.get(Domain, domain)

            if not domain_obj:
                return False

            session.delete(domain_obj)
            session.commit()

            return True

    def domain_exists(self, domain: str) -> bool:
        """
        Check if domain exists in database.

        Args:
            domain: Domain name to check

        Returns:
            True if domain exists, False otherwise
        """
        with Session(self.engine) as session:
            query = select(Domain).where(Domain.domain == domain)
            result = session.exec(query).first()
            return result is not None

    # ============================================================================
    # Scan Management
    # ============================================================================

    def create_scan_session(
        self,
        scan_type: str,
        domains: List[str],
        tool_name: Optional[str] = None
    ) -> str:
        """
        Create a new scan session and return scan_id.

        Args:
            scan_type: Type of scan (passive_subdomain_enum, active_port_scan, etc.)
            domains: List of domains being scanned
            tool_name: Optional tool name (subfinder, amass, nmap, naabu)

        Returns:
            Scan ID (UUID)
        """
        with Session(self.engine) as session:
            scan_id = str(uuid.uuid4())
            now = get_ist_now()

            # Convert domains list to JSON string
            domains_json = json.dumps(domains)

            scan = ScanSession(
                scan_id=scan_id,
                scan_type=scan_type,
                tool_name=tool_name,
                domains_scanned=domains_json,
                start_time=now,
                end_time=None,
                status='running',
                findings_count=0
            )

            session.add(scan)
            session.commit()

            return scan_id

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        end_time: Optional[datetime] = None,
        findings_count: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Update scan session status.

        Args:
            scan_id: Scan ID to update
            status: New status (running, completed, failed)
            end_time: Optional end time
            findings_count: Optional number of findings

        Returns:
            Dictionary with success status
        """
        with Session(self.engine) as session:
            scan = session.get(ScanSession, scan_id)

            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            scan.status = status

            if end_time:
                scan.end_time = end_time
            elif status in ['completed', 'failed']:
                scan.end_time = get_ist_now()

            if findings_count is not None:
                scan.findings_count = findings_count

            session.add(scan)
            session.commit()

        return {'success': True}

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan session information.

        Args:
            scan_id: Scan ID to retrieve

        Returns:
            Dictionary with scan information or None if not found
        """
        with Session(self.engine) as session:
            scan = session.get(ScanSession, scan_id)

            if not scan:
                return None

            return self._scan_to_dict(scan)

    def get_scan_history(
        self,
        limit: int = 50,
        offset: int = 0,
        domain: Optional[str] = None,
        scan_type: Optional[str] = None,
        tool_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get scan history with optional filters.

        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip
            domain: Filter by domain
            scan_type: Filter by scan type
            tool_name: Filter by tool name

        Returns:
            Dictionary with scans list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Build query
            query = select(ScanSession)

            # Apply filters
            if domain:
                # Search in domains_scanned JSON array
                query = query.where(ScanSession.domains_scanned.contains(domain))
            if scan_type:
                query = query.where(ScanSession.scan_type == scan_type)
            if tool_name:
                query = query.where(ScanSession.tool_name == tool_name)

            # Get total count
            count_query = select(func.count()).select_from(ScanSession)
            if domain:
                count_query = count_query.where(ScanSession.domains_scanned.contains(domain))
            if scan_type:
                count_query = count_query.where(ScanSession.scan_type == scan_type)
            if tool_name:
                count_query = count_query.where(ScanSession.tool_name == tool_name)

            total_count = session.exec(count_query).one()

            # Apply pagination and ordering
            query = query.order_by(ScanSession.start_time.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            scans = session.exec(query).all()

            return {
                'scans': [self._scan_to_dict(s) for s in scans],
                'total_count': total_count,
                'has_more': (offset + len(scans)) < total_count,
                'limit': limit,
                'offset': offset
            }

    # ============================================================================
    # Security Alerts
    # ============================================================================

    def store_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Store security alerts from scan results as findings.

        Alerts are now stored as findings in the analysis layer for
        unified management with risk scoring and advanced analysis features.

        Args:
            alerts: List of alert dictionaries with fields:
                - domain: Domain name (maps to affected_asset)
                - scan_id: Associated scan ID
                - vulnerability_type: Type of vulnerability (maps to finding_type)
                - severity: Severity level (critical, high, medium, low, info)
                - description: Alert description (maps to title)
                - remediation: Optional remediation steps
                - tool_source: Tool that generated the alert (maps to detector)
                - discovered_at: Discovery timestamp

        Returns:
            Dictionary with success status and count of stored alerts
        """
        # Map old alert schema to new finding schema
        findings = []
        for alert in alerts:
            finding = {
                'scan_id': alert['scan_id'],
                'finding_type': alert.get('vulnerability_type', 'unknown'),  # Map field name
                'affected_asset': alert.get('domain', alert.get('affected_asset', 'unknown')),
                'title': alert.get('description', alert.get('title', 'Alert')),
                'description': alert.get('description'),
                'severity': alert.get('severity', 'info'),
                'risk_score': alert.get('risk_score', 50),
                'detector': alert.get('tool_source', alert.get('detector')),
                'port': alert.get('port'),
                'protocol': alert.get('protocol'),
                'remediation': alert.get('remediation'),
                'discovered_at': alert.get('discovered_at')
            }
            findings.append(finding)

        self.store_findings(findings)

        return {
            'success': True,
            'count': len(findings)
        }

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific alert by ID (now uses findings from analysis layer).

        Args:
            alert_id: Alert/Finding ID to retrieve

        Returns:
            Dictionary containing alert/finding details, or None if not found
        """
        return self.get_finding_by_id(alert_id)

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity_filter: Optional[List[str]] = None,
        severity: Optional[str] = None,
        domain: Optional[str] = None,
        scan_id: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get paginated security alerts with optional filtering.

        Alerts are now retrieved from the findings table in the analysis layer.

        Args:
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            severity_filter: List of severity levels to filter by
            severity: Single severity level to filter by (convenience parameter)
            domain: Filter by affected asset/domain
            scan_id: Filter by scan ID
            min_severity: Minimum severity level

        Returns:
            Dictionary with alerts list, total count, and pagination info
        """
        # Use findings API which now handles all alerts
        # Map severity parameter to min_severity if not already set
        if severity and not min_severity:
            min_severity = severity

        result = self.get_findings(
            limit=limit,
            offset=offset,
            affected_asset=domain,
            scan_id=scan_id,
            min_severity=min_severity
        )

        # Map findings response to alerts response for backwards compatibility
        return {
            'alerts': result.get('findings', []),
            'total_count': result.get('total_count', 0),
            'limit': result.get('limit', limit),
            'offset': result.get('offset', offset)
        }

    # ============================================================================
    # Subdomain History
    # ============================================================================

    def add_subdomain_to_history(
        self,
        apex_domain: str,
        subdomain: str,
        scan_id: str,
        status: str = 'new',
        tool_source: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add subdomain to history tracking.

        Args:
            apex_domain: Apex domain (e.g., example.com)
            subdomain: Full subdomain (e.g., sub.example.com)
            scan_id: Associated scan ID
            status: Status (new, existing, removed)
            tool_source: Tool that discovered the subdomain
            metadata: Optional metadata dictionary
        """
        with Session(self.engine) as session:
            now = get_ist_now()
            history_id = str(uuid.uuid4())

            # Convert metadata to JSON string
            metadata_json = json.dumps(metadata) if metadata else None

            history = SubdomainHistory(
                id=history_id,
                apex_domain=apex_domain,
                subdomain=subdomain,
                scan_id=scan_id,
                status=status,
                first_seen=now,
                last_seen=now,
                tool_source=tool_source,
                meta_data=metadata_json
            )

            session.add(history)
            session.commit()

    def store_subdomain_history(
        self,
        apex_domain: str,
        subdomain: str,
        scan_id: str,
        status: str = 'new',
        tool_source: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Store subdomain history (alias for add_subdomain_to_history with return value).

        Args:
            apex_domain: Apex domain (e.g., example.com)
            subdomain: Full subdomain (e.g., sub.example.com)
            scan_id: Associated scan ID
            status: Status (new, existing, removed)
            tool_source: Tool that discovered the subdomain
            metadata: Optional metadata dictionary

        Returns:
            Dictionary with success status
        """
        self.add_subdomain_to_history(
            apex_domain=apex_domain,
            subdomain=subdomain,
            scan_id=scan_id,
            status=status,
            tool_source=tool_source,
            metadata=metadata
        )
        return {'success': True}

    def get_subdomain_history(
        self,
        domain: str,
        limit: int = 100,
        offset: int = 0,
        status_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get subdomain history for a domain.

        Args:
            domain: Apex domain
            limit: Maximum number of records to return
            offset: Number of records to skip
            status_filter: Filter by status (new, existing, removed)

        Returns:
            Dictionary with history list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Build query
            query = select(SubdomainHistory).where(
                SubdomainHistory.apex_domain == domain
            )

            # Apply status filter
            if status_filter:
                query = query.where(SubdomainHistory.status == status_filter)

            # Get total count
            count_query = select(func.count()).select_from(SubdomainHistory).where(
                SubdomainHistory.apex_domain == domain
            )
            if status_filter:
                count_query = count_query.where(SubdomainHistory.status == status_filter)

            total_count = session.exec(count_query).one()

            # Apply pagination and ordering
            query = query.order_by(SubdomainHistory.last_seen.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            history = session.exec(query).all()

            return {
                'history': [self._subdomain_history_to_dict(h) for h in history],
                'total_count': total_count,
                'has_more': (offset + len(history)) < total_count,
                'limit': limit,
                'offset': offset
            }

    def get_subdomain_changes(
        self,
        domain: str,
        scan_id: str
    ) -> Dict[str, List[str]]:
        """
        Get subdomain changes from a specific scan.

        Args:
            domain: Apex domain
            scan_id: Scan ID

        Returns:
            Dictionary with 'new', 'existing', and 'removed' subdomain lists
        """
        with Session(self.engine) as session:
            # Get all subdomains from this scan
            query = select(SubdomainHistory).where(
                and_(
                    SubdomainHistory.apex_domain == domain,
                    SubdomainHistory.scan_id == scan_id
                )
            )

            history = session.exec(query).all()

            changes = {
                'new': [],
                'existing': [],
                'removed': []
            }

            for record in history:
                if record.status in changes:
                    changes[record.status].append(record.subdomain)

            return changes

    # ============================================================================
    # Tool Results Storage
    # ============================================================================

    def store_subfinder_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store Subfinder scan results.

        Args:
            results: List of result dictionaries with fields:
                - scan_id: Scan ID
                - apex_domain: Apex domain
                - subdomain: Discovered subdomain
                - source: Optional source
                - discovered_at: Discovery timestamp
                - raw_json: Optional raw JSON data
        """
        with Session(self.engine) as session:
            for result_data in results:
                result_id = str(uuid.uuid4())

                result = SubfinderResult(
                    id=result_id,
                    scan_id=result_data.get('scan_id'),
                    apex_domain=result_data.get('apex_domain'),
                    subdomain=result_data.get('subdomain'),
                    source=result_data.get('source'),
                    discovered_at=result_data.get('discovered_at', get_ist_now()),
                    raw_json=result_data.get('raw_json')
                )

                session.add(result)

            session.commit()

    def store_amass_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store Amass scan results.

        Args:
            results: List of result dictionaries (same format as Subfinder)
        """
        with Session(self.engine) as session:
            for result_data in results:
                result_id = str(uuid.uuid4())

                result = AmassResult(
                    id=result_id,
                    scan_id=result_data.get('scan_id'),
                    apex_domain=result_data.get('apex_domain'),
                    subdomain=result_data.get('subdomain'),
                    source=result_data.get('source'),
                    discovered_at=result_data.get('discovered_at', get_ist_now()),
                    raw_json=result_data.get('raw_json')
                )

                session.add(result)

            session.commit()

    def store_nmap_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store Nmap scan results.

        Args:
            results: List of result dictionaries with fields:
                - scan_id: Scan ID
                - target_host: Target host
                - port: Port number
                - protocol: Protocol (tcp, udp)
                - service_name: Optional service name
                - service_version: Optional service version
                - discovered_at: Discovery timestamp
                - raw_json: Optional raw JSON data
        """
        with Session(self.engine) as session:
            for result_data in results:
                result_id = str(uuid.uuid4())

                result = NmapResult(
                    id=result_id,
                    scan_id=result_data.get('scan_id'),
                    target_host=result_data.get('target_host'),
                    port=result_data.get('port'),
                    protocol=result_data.get('protocol', 'tcp'),
                    service_name=result_data.get('service_name'),
                    service_version=result_data.get('service_version'),
                    discovered_at=result_data.get('discovered_at', get_ist_now()),
                    raw_json=result_data.get('raw_json')
                )

                session.add(result)

            session.commit()

    def store_naabu_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Store Naabu scan results.

        Args:
            results: List of result dictionaries with fields:
                - scan_id: Scan ID
                - target_host: Target host
                - port: Port number
                - protocol: Protocol (tcp, udp)
                - discovered_at: Discovery timestamp
                - raw_json: Optional raw JSON data
        """
        with Session(self.engine) as session:
            for result_data in results:
                result_id = str(uuid.uuid4())

                result = NaabuResult(
                    id=result_id,
                    scan_id=result_data.get('scan_id'),
                    target_host=result_data.get('target_host'),
                    port=result_data.get('port'),
                    protocol=result_data.get('protocol', 'tcp'),
                    ip=result_data.get('ip'),
                    discovered_at=result_data.get('discovered_at', get_ist_now()),
                    raw_json=result_data.get('raw_json')
                )

                session.add(result)

            session.commit()

    def get_tool_results(
        self,
        scan_id: str,
        tool_name: str,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get tool-specific results for a scan.

        Args:
            scan_id: Scan ID
            tool_name: Tool name (subfinder, amass, nmap, naabu)
            limit: Maximum number of results to return
            offset: Number of results to skip

        Returns:
            Dictionary with results list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Select appropriate model based on tool name
            model_map = {
                'subfinder': SubfinderResult,
                'amass': AmassResult,
                'nmap': NmapResult,
                'naabu': NaabuResult
            }

            model = model_map.get(tool_name.lower())
            if not model:
                raise ValueError(f"Unknown tool: {tool_name}")

            # Build query
            query = select(model).where(model.scan_id == scan_id)

            # Get total count
            count_query = select(func.count()).select_from(model).where(
                model.scan_id == scan_id
            )
            total_count = session.exec(count_query).one()

            # Apply pagination and ordering
            query = query.order_by(model.discovered_at.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            results = session.exec(query).all()

            # Convert to dicts
            converter_map = {
                'subfinder': self._subfinder_result_to_dict,
                'amass': self._amass_result_to_dict,
                'nmap': self._nmap_result_to_dict,
                'naabu': self._naabu_result_to_dict
            }

            converter = converter_map[tool_name.lower()]

            return {
                'results': [converter(r) for r in results],
                'total_count': total_count,
                'has_more': (offset + len(results)) < total_count,
                'limit': limit,
                'offset': offset
            }

    # ============================================================================
    # Deletion Operations
    # ============================================================================

    def get_deletion_preview(self, domain: str) -> Dict[str, Any]:
        """
        Get preview of data that would be deleted with a domain.

        Args:
            domain: Domain to preview deletion for

        Returns:
            Dictionary with counts of associated data
        """
        with Session(self.engine) as session:
            preview = {
                'domain': domain,
                'totals': {}
            }

            # Count scan sessions
            scan_count = session.exec(
                select(func.count()).select_from(ScanSession).where(
                    ScanSession.domains_scanned.contains(domain)
                )
            ).one()
            preview['totals']['scan_sessions'] = scan_count

            # Count findings (security alerts now stored as findings)
            finding_count = session.exec(
                select(func.count()).select_from(Finding).where(
                    Finding.affected_asset == domain
                )
            ).one()
            preview['totals']['findings'] = finding_count
            preview['totals']['security_alerts'] = finding_count  # Backward compat

            # Count subdomain history
            subdomain_history_count = session.exec(
                select(func.count()).select_from(SubdomainHistory).where(
                    SubdomainHistory.apex_domain == domain
                )
            ).one()
            preview['totals']['subdomain_history'] = subdomain_history_count

            # Count tool results
            subfinder_count = session.exec(
                select(func.count()).select_from(SubfinderResult).where(
                    SubfinderResult.apex_domain == domain
                )
            ).one()
            preview['totals']['subfinder_results'] = subfinder_count

            amass_count = session.exec(
                select(func.count()).select_from(AmassResult).where(
                    AmassResult.apex_domain == domain
                )
            ).one()
            preview['totals']['amass_results'] = amass_count

            # Nmap and Naabu counts
            nmap_count = session.exec(
                select(func.count()).select_from(NmapResult).where(
                    NmapResult.target_host.contains(domain)
                )
            ).one()
            preview['totals']['nmap_results'] = nmap_count

            naabu_count = session.exec(
                select(func.count()).select_from(NaabuResult).where(
                    NaabuResult.target_host.contains(domain)
                )
            ).one()
            preview['totals']['naabu_results'] = naabu_count

            # Calculate total
            total = sum([
                scan_count,
                finding_count,
                subdomain_history_count,
                subfinder_count,
                amass_count,
                nmap_count,
                naabu_count
            ])
            preview['totals']['total_records'] = total

            # Add placeholder counts for tool-specific history (for UI compatibility)
            preview['totals']['subfinder_history'] = 0
            preview['totals']['amass_history'] = 0
            preview['totals']['nmap_history'] = 0
            preview['totals']['naabu_history'] = 0

            return preview

    def delete_domain_with_data(self, domain: str) -> Dict[str, int]:
        """
        Delete domain and all associated data.

        Args:
            domain: Domain to delete

        Returns:
            Dictionary with counts of deleted records by category
        """
        with Session(self.engine) as session:
            deleted = {}

            # Delete subdomain history
            result = session.exec(
                delete(SubdomainHistory).where(
                    SubdomainHistory.apex_domain == domain
                )
            )
            deleted['subdomain_history'] = result.rowcount
            session.commit()

            # Delete findings (security alerts now stored as findings)
            result = session.exec(
                delete(Finding).where(
                    Finding.affected_asset == domain
                )
            )
            deleted['findings'] = result.rowcount
            deleted['security_alerts'] = result.rowcount  # Backward compat
            session.commit()

            # Delete tool results
            result = session.exec(
                delete(SubfinderResult).where(
                    SubfinderResult.apex_domain == domain
                )
            )
            deleted['subfinder_results'] = result.rowcount
            session.commit()

            result = session.exec(
                delete(AmassResult).where(
                    AmassResult.apex_domain == domain
                )
            )
            deleted['amass_results'] = result.rowcount
            session.commit()

            result = session.exec(
                delete(NmapResult).where(
                    NmapResult.target_host.contains(domain)
                )
            )
            deleted['nmap_results'] = result.rowcount
            session.commit()

            result = session.exec(
                delete(NaabuResult).where(
                    NaabuResult.target_host.contains(domain)
                )
            )
            deleted['naabu_results'] = result.rowcount
            session.commit()

            # Delete scan sessions
            result = session.exec(
                delete(ScanSession).where(
                    ScanSession.domains_scanned.contains(domain)
                )
            )
            deleted['scan_sessions'] = result.rowcount
            session.commit()

            # Finally, delete the domain itself
            domain_obj = session.get(Domain, domain)
            if domain_obj:
                session.delete(domain_obj)
                session.commit()
                deleted['domain'] = 1
            else:
                deleted['domain'] = 0

            return deleted

    # ============================================================================
    # System Metrics
    # ============================================================================

    def get_system_metrics(self) -> Dict[str, Any]:
        """
        Get system metrics and performance data.

        Returns:
            Dictionary with system metrics
        """
        with Session(self.engine) as session:
            metrics = {}

            # Domain metrics
            metrics['total_domains'] = session.exec(
                select(func.count()).select_from(Domain)
            ).one()

            metrics['primary_domains'] = session.exec(
                select(func.count()).select_from(Domain).where(
                    Domain.is_primary == True
                )
            ).one()

            # Scan metrics
            metrics['total_scans'] = session.exec(
                select(func.count()).select_from(ScanSession)
            ).one()

            metrics['completed_scans'] = session.exec(
                select(func.count()).select_from(ScanSession).where(
                    ScanSession.status == 'completed'
                )
            ).one()

            metrics['failed_scans'] = session.exec(
                select(func.count()).select_from(ScanSession).where(
                    ScanSession.status == 'failed'
                )
            ).one()

            metrics['running_scans'] = session.exec(
                select(func.count()).select_from(ScanSession).where(
                    ScanSession.status == 'running'
                )
            ).one()

            # Finding/Alert metrics (alerts now stored as findings)
            metrics['total_alerts'] = session.exec(
                select(func.count()).select_from(Finding)
            ).one()
            metrics['total_findings'] = metrics['total_alerts']  # Same thing now

            # Finding/Alert breakdown by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = session.exec(
                    select(func.count()).select_from(Finding).where(
                        Finding.severity == severity
                    )
                ).one()
                metrics[f'{severity}_alerts'] = count
                metrics[f'{severity}_findings'] = count  # Same thing now

            # Subdomain metrics
            metrics['total_subdomains'] = session.exec(
                select(func.count()).select_from(SubdomainHistory)
            ).one()

            metrics['new_subdomains'] = session.exec(
                select(func.count()).select_from(SubdomainHistory).where(
                    SubdomainHistory.status == 'new'
                )
            ).one()

            return metrics

    def get_health_status(self) -> Dict[str, bool]:
        """
        Get database health status.

        Returns:
            Dictionary with health check results
        """
        try:
            with Session(self.engine) as session:
                # Test database connectivity
                session.exec(select(func.count()).select_from(Domain))

                return {
                    'database_connected': True,
                    'tables_exist': True,
                    'healthy': True
                }
        except Exception as e:
            return {
                'database_connected': False,
                'tables_exist': False,
                'healthy': False,
                'error': str(e)
            }

    def get_domain_count(self) -> int:
        """
        Get total count of domains.

        Returns:
            Number of domains
        """
        with Session(self.engine) as session:
            return session.exec(
                select(func.count()).select_from(Domain)
            ).one()

    def get_scan_count(self) -> int:
        """
        Get total count of scans.

        Returns:
            Number of scans
        """
        with Session(self.engine) as session:
            return session.exec(
                select(func.count()).select_from(ScanSession)
            ).one()

    def get_alert_count(self) -> int:
        """
        Get total count of security alerts.

        Returns:
            Number of alerts
        """
        with Session(self.engine) as session:
            return session.exec(
                select(func.count()).select_from(Finding)
            ).one()

    # ============================================================================
    # Findings and Analysis Layer
    # ============================================================================

    def store_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Store analysis findings in database.

        Args:
            findings: List of finding dictionaries with fields:
                - id: Finding UUID
                - scan_id: Scan session UUID
                - finding_type: Type of finding
                - affected_asset: Domain/subdomain/IP
                - title: Finding title
                - description: Detailed description
                - severity: critical/high/medium/low/info
                - risk_score: Numeric score (0-100)
                - evidence_json: JSON string with evidence
                - remediation: Remediation guidance
                - detector: Detector name
                - And other optional fields...
        """
        with Session(self.engine) as session:
            for finding_data in findings:
                # Create Finding object
                finding = Finding(
                    id=finding_data.get('id', str(uuid.uuid4())),
                    scan_id=finding_data['scan_id'],
                    finding_type=finding_data['finding_type'],
                    affected_asset=finding_data['affected_asset'],
                    port=finding_data.get('port'),
                    protocol=finding_data.get('protocol'),
                    title=finding_data['title'],
                    description=finding_data.get('description'),
                    service_name=finding_data.get('service_name'),
                    severity=finding_data.get('severity', 'medium'),
                    risk_score=finding_data.get('risk_score', 50),
                    confidence_level=finding_data.get('confidence_level', 'medium'),
                    evidence_json=json.dumps(finding_data.get('evidence', {})),
                    cwe_id=finding_data.get('cwe_id'),
                    remediation=finding_data.get('remediation'),
                    detector=finding_data.get('detector'),
                    score_breakdown_json=json.dumps(finding_data.get('score_breakdown', {})),
                    status='open',
                    false_positive=False,
                    discovered_at=get_ist_now(),
                    updated_at=get_ist_now()
                )
                session.add(finding)

            session.commit()

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        affected_asset: Optional[str] = None,
        min_severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieve findings with optional filters.

        Args:
            scan_id: Filter by scan ID
            affected_asset: Filter by affected asset
            min_severity: Minimum severity (critical/high/medium/low/info)
            limit: Maximum number of findings to return
            offset: Number of findings to skip

        Returns:
            Dictionary with findings list, total count, and pagination info
        """
        severity_order = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }

        with Session(self.engine) as session:
            # Build query
            query = select(Finding)

            # Apply filters
            filters = []
            if scan_id:
                filters.append(Finding.scan_id == scan_id)
            if affected_asset:
                filters.append(Finding.affected_asset == affected_asset)
            if min_severity and min_severity in severity_order:
                min_order = severity_order[min_severity]
                valid_severities = [s for s, o in severity_order.items() if o >= min_order]
                filters.append(Finding.severity.in_(valid_severities))

            if filters:
                query = query.where(and_(*filters))

            # Get total count
            count_query = select(func.count()).select_from(Finding)
            if filters:
                count_query = count_query.where(and_(*filters))
            total_count = session.exec(count_query).one()

            # Apply pagination and ordering (highest risk first)
            query = query.order_by(Finding.risk_score.desc(), Finding.discovered_at.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            findings = session.exec(query).all()

            return {
                'findings': [self._finding_to_dict(f) for f in findings],
                'total_count': total_count,
                'has_more': (offset + len(findings)) < total_count,
                'limit': limit,
                'offset': offset
            }

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific finding by ID.

        Args:
            finding_id: Finding UUID

        Returns:
            Finding dictionary or None if not found
        """
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if finding:
                return self._finding_to_dict(finding)
            return None

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """
        Update finding status.

        Args:
            finding_id: Finding UUID
            status: New status (open/acknowledged/resolved/false_positive)
            resolution_notes: Optional resolution notes

        Returns:
            True if updated, False if finding not found
        """
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                return False

            finding.status = status
            finding.updated_at = get_ist_now()

            if status == 'resolved':
                finding.resolved_at = get_ist_now()
            if status == 'false_positive':
                finding.false_positive = True

            if resolution_notes:
                finding.resolution_notes = resolution_notes

            session.add(finding)
            session.commit()
            return True

    def get_findings_statistics(
        self,
        scan_id: Optional[str] = None,
        affected_asset: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get statistics about findings.

        Args:
            scan_id: Filter by scan ID
            affected_asset: Filter by affected asset

        Returns:
            Dictionary with statistics
        """
        with Session(self.engine) as session:
            # Build base query
            query = select(Finding)
            filters = []

            if scan_id:
                filters.append(Finding.scan_id == scan_id)
            if affected_asset:
                filters.append(Finding.affected_asset == affected_asset)

            if filters:
                query = query.where(and_(*filters))

            findings = session.exec(query).all()

            # Calculate statistics
            total = len(findings)
            by_severity = {}
            by_status = {}
            total_risk_score = 0

            for finding in findings:
                # Count by severity
                severity = finding.severity
                by_severity[severity] = by_severity.get(severity, 0) + 1

                # Count by status
                status = finding.status
                by_status[status] = by_status.get(status, 0) + 1

                # Sum risk scores
                total_risk_score += finding.risk_score

            return {
                'total_findings': total,
                'by_severity': by_severity,
                'by_status': by_status,
                'average_risk_score': round(total_risk_score / total, 2) if total > 0 else 0,
                'critical_findings': by_severity.get('critical', 0),
                'high_findings': by_severity.get('high', 0),
                'medium_findings': by_severity.get('medium', 0),
                'low_findings': by_severity.get('low', 0),
                'info_findings': by_severity.get('info', 0),
                'open_findings': by_status.get('open', 0),
                'resolved_findings': by_status.get('resolved', 0),
                'false_positives': by_status.get('false_positive', 0)
            }

    # ============================================================================
    # Helper Methods (Internal)
    # ============================================================================

    def _scan_to_dict(self, scan: ScanSession) -> Dict[str, Any]:
        """Convert ScanSession object to dictionary."""
        # Parse domains_scanned JSON string to list
        domains = json.loads(scan.domains_scanned) if scan.domains_scanned else []

        return {
            'scan_id': scan.scan_id,
            'scan_type': scan.scan_type,
            'tool_name': scan.tool_name,
            'domains_scanned': domains,
            'start_time': scan.start_time,
            'end_time': scan.end_time,
            'status': scan.status,
            'findings_count': scan.findings_count
        }

    def _subdomain_history_to_dict(self, history: SubdomainHistory) -> Dict[str, Any]:
        """Convert SubdomainHistory object to dictionary."""
        # Parse metadata JSON string to dict
        metadata = json.loads(history.meta_data) if history.meta_data else {}

        return {
            'id': history.id,
            'apex_domain': history.apex_domain,
            'subdomain': history.subdomain,
            'scan_id': history.scan_id,
            'status': history.status,
            'first_seen': history.first_seen,
            'last_seen': history.last_seen,
            'tool_source': history.tool_source,
            'metadata': metadata
        }

    def _subfinder_result_to_dict(self, result: SubfinderResult) -> Dict[str, Any]:
        """Convert SubfinderResult object to dictionary."""
        return {
            'id': result.id,
            'scan_id': result.scan_id,
            'apex_domain': result.apex_domain,
            'subdomain': result.subdomain,
            'source': result.source,
            'discovered_at': result.discovered_at,
            'raw_json': result.raw_json
        }

    def _amass_result_to_dict(self, result: AmassResult) -> Dict[str, Any]:
        """Convert AmassResult object to dictionary."""
        return {
            'id': result.id,
            'scan_id': result.scan_id,
            'apex_domain': result.apex_domain,
            'subdomain': result.subdomain,
            'source': result.source,
            'discovered_at': result.discovered_at,
            'raw_json': result.raw_json
        }

    def _nmap_result_to_dict(self, result: NmapResult) -> Dict[str, Any]:
        """Convert NmapResult object to dictionary."""
        return {
            'id': result.id,
            'scan_id': result.scan_id,
            'target_host': result.target_host,
            'port': result.port,
            'protocol': result.protocol,
            'service_name': result.service_name,
            'service_version': result.service_version,
            'discovered_at': result.discovered_at,
            'raw_json': result.raw_json
        }

    def _naabu_result_to_dict(self, result: NaabuResult) -> Dict[str, Any]:
        """Convert NaabuResult object to dictionary."""
        return {
            'id': result.id,
            'scan_id': result.scan_id,
            'target_host': result.target_host,
            'port': result.port,
            'protocol': result.protocol,
            'ip': result.ip,
            'discovered_at': result.discovered_at,
            'raw_json': result.raw_json
        }

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert Finding object to dictionary."""
        # Parse JSON fields
        evidence = {}
        score_breakdown = {}

        try:
            if finding.evidence_json:
                evidence = json.loads(finding.evidence_json)
        except (json.JSONDecodeError, TypeError):
            pass

        try:
            if finding.score_breakdown_json:
                score_breakdown = json.loads(finding.score_breakdown_json)
        except (json.JSONDecodeError, TypeError):
            pass

        return {
            'id': finding.id,
            'scan_id': finding.scan_id,
            'finding_type': finding.finding_type,
            'affected_asset': finding.affected_asset,
            'port': finding.port,
            'protocol': finding.protocol,
            'title': finding.title,
            'description': finding.description,
            'service_name': finding.service_name,
            'severity': finding.severity,
            'risk_score': finding.risk_score,
            'confidence_level': finding.confidence_level,
            'evidence': evidence,
            'cwe_id': finding.cwe_id,
            'remediation': finding.remediation,
            'detector': finding.detector,
            'score_breakdown': score_breakdown,
            'status': finding.status,
            'false_positive': finding.false_positive,
            'resolved_at': finding.resolved_at,
            'resolution_notes': finding.resolution_notes,
            'discovered_at': finding.discovered_at,
            'updated_at': finding.updated_at
        }

    # ============================================================================
    # API Key Management
    # ============================================================================

    def create_api_key(
        self,
        key_hash: str,
        name: str,
        permissions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new API key.

        Args:
            key_hash: SHA-256 hash of the API key
            name: Human-readable name for the key
            permissions: List of permissions (e.g., ["domain:write", "scan:execute"])

        Returns:
            Dictionary with API key information
        """
        with Session(self.engine) as session:
            api_key = APIKey(
                key=key_hash,
                name=name,
                permissions=json.dumps(permissions or [])
            )
            session.add(api_key)
            session.commit()
            session.refresh(api_key)

            return {
                'id': api_key.id,
                'name': api_key.name,
                'permissions': json.loads(api_key.permissions),
                'created_at': api_key.created_at,
                'expires_at': api_key.expires_at,
                'is_active': api_key.is_active
            }

    def get_api_key_by_hash(self, key_hash: str, include_inactive: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key
            include_inactive: If True, include revoked keys in results

        Returns:
            API key information or None if not found
        """
        with Session(self.engine) as session:
            if include_inactive:
                query = select(APIKey).where(APIKey.key == key_hash)
            else:
                query = select(APIKey).where(
                    and_(
                        APIKey.key == key_hash,
                        APIKey.is_active == True
                    )
                )
            api_key = session.exec(query).first()

            if not api_key:
                return None

            # Update last_used_at only if key is active
            if api_key.is_active:
                api_key.last_used_at = get_ist_now()
                session.add(api_key)
                session.commit()

            return {
                'id': api_key.id,
                'name': api_key.name,
                'permissions': json.loads(api_key.permissions),
                'created_at': api_key.created_at,
                'expires_at': api_key.expires_at,
                'last_used_at': api_key.last_used_at,
                'is_active': api_key.is_active
            }

    def list_api_keys(self) -> List[Dict[str, Any]]:
        """
        List all API keys.

        Returns:
            List of API key information dictionaries
        """
        with Session(self.engine) as session:
            query = select(APIKey).order_by(APIKey.created_at.desc())
            api_keys = session.exec(query).all()

            return [
                {
                    'id': key.id,
                    'name': key.name,
                    'permissions': json.loads(key.permissions),
                    'created_at': key.created_at,
                    'expires_at': key.expires_at,
                    'last_used_at': key.last_used_at,
                    'is_active': key.is_active
                }
                for key in api_keys
            ]

    def revoke_api_key(self, key_id: str) -> bool:
        """
        Revoke an API key by ID.

        Args:
            key_id: API key ID

        Returns:
            True if revoked, False if not found
        """
        with Session(self.engine) as session:
            query = select(APIKey).where(APIKey.id == key_id)
            api_key = session.exec(query).first()

            if not api_key:
                return False

            api_key.is_active = False
            session.add(api_key)
            session.commit()
            return True

    # ============================================================================
    # Audit Logging
    # ============================================================================

    def create_audit_log(
        self,
        endpoint: str,
        method: str,
        resource_type: str,
        action: str,
        ip_address: str,
        response_status: int,
        success: bool,
        api_key_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_body: Optional[str] = None
    ) -> str:
        """
        Create an audit log entry.

        Args:
            endpoint: API endpoint path
            method: HTTP method
            resource_type: Type of resource (domain, scan, analysis)
            action: Action performed (create, update, delete, execute)
            ip_address: Client IP address
            response_status: HTTP response status code
            success: Whether the operation succeeded
            api_key_id: Optional API key ID
            resource_id: Optional resource ID
            user_agent: Optional user agent string
            request_body: Optional JSON request body

        Returns:
            Audit log ID
        """
        with Session(self.engine) as session:
            audit_log = AuditLog(
                api_key_id=api_key_id,
                endpoint=endpoint,
                method=method,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                ip_address=ip_address,
                user_agent=user_agent,
                request_body=request_body,
                response_status=response_status,
                success=success
            )
            session.add(audit_log)
            session.commit()
            session.refresh(audit_log)
            return audit_log.id

    def get_audit_logs(
        self,
        limit: int = 100,
        resource_type: Optional[str] = None,
        api_key_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit logs with optional filtering.

        Args:
            limit: Maximum number of logs to return
            resource_type: Optional filter by resource type
            api_key_id: Optional filter by API key ID

        Returns:
            List of audit log dictionaries
        """
        with Session(self.engine) as session:
            query = select(AuditLog)

            # Apply filters
            if resource_type:
                query = query.where(AuditLog.resource_type == resource_type)
            if api_key_id:
                query = query.where(AuditLog.api_key_id == api_key_id)

            # Order by timestamp descending and limit
            query = query.order_by(AuditLog.timestamp.desc()).limit(limit)

            logs = session.exec(query).all()

            return [
                {
                    'id': log.id,
                    'timestamp': log.timestamp,
                    'api_key_id': log.api_key_id,
                    'endpoint': log.endpoint,
                    'method': log.method,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'action': log.action,
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent,
                    'response_status': log.response_status,
                    'success': log.success
                }
                for log in logs
            ]
