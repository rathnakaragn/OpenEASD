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
from typing import List, Dict, Optional, Any, TypedDict

from sqlmodel import SQLModel, Session, create_engine, select, func, and_, or_, delete

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
# Import finding models from data layer (proper layering)
from src.data.models.finding import (
    Finding,
    Vulnerability,
    CVEMapping,
    FindingGroup
)
from src.data.models.job import Job
# Import converters for model-to-dict conversion (eliminates duplicate code)
from src.data.converters import (
    ScanConverter,
    ToolResultConverter,
    FindingConverter
)
# Import DTOs for improved type hints (QA enhancement)
from src.data.dto import (
    JobDTO,
    JobStatisticsDTO,
    FindingStatisticsDTO
)
from src.utils.timezone import get_ist_now, to_ist
from src.utils.config import Config


# TypedDict definitions for improved type hints (QA enhancement)
class JobDict(TypedDict, total=False):
    """Type hint for job dictionary returned by database methods."""
    id: str
    job_type: str
    payload: Dict[str, Any]
    status: str
    scan_id: Optional[str]
    created_at: Optional[str]
    queued_at: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    worker_id: Optional[str]
    error_message: Optional[str]
    retry_count: int
    max_retries: int
    priority: int


class JobListResult(TypedDict):
    """Type hint for paginated job list result."""
    jobs: List[JobDict]
    total: int
    has_more: bool


def _escape_sql_wildcards(value: str) -> str:
    """
    Escape SQL wildcard characters to prevent SQL injection in LIKE queries.

    The .contains() method uses LIKE with wildcards. User input containing
    '%' or '_' could alter query behavior without escaping.

    Args:
        value: User-provided string value

    Returns:
        Escaped string safe for use in LIKE queries
    """
    # Escape backslash first, then wildcards
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


class SQLModelManager(DatabaseManager):
    """SQLModel implementation of DatabaseManager using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize SQLModel database manager.

        Args:
            db_path: Path to SQLite database file (default: from config or data/openeasd.db)
        """
        if db_path is None:
            config = Config()
            db_path = config.get('database.database_path', 'data/openeasd.db')

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
        """Initialize database and create all tables if they don't exist."""
        # checkfirst=True ensures tables are only created if they don't exist
        SQLModel.metadata.create_all(self.engine, checkfirst=True)

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

    def increment_domain_scan_count(self, domain: str) -> Domain:
        """
        Increment scan count and update last_scanned_at for a domain.

        Called after a successful scan completion.

        Args:
            domain: Domain name to update

        Returns:
            The updated domain object.
        """
        with Session(self.engine) as session:
            domain_obj = session.get(Domain, domain)

            if not domain_obj:
                raise ValueError(f"Domain {domain} not found")

            # Increment scan count
            domain_obj.scan_count += 1
            domain_obj.last_scanned_at = get_ist_now()
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
                # Search in domains_scanned JSON array (escape wildcards for security)
                escaped_domain = _escape_sql_wildcards(domain)
                query = query.where(ScanSession.domains_scanned.contains(escaped_domain))
            if scan_type:
                query = query.where(ScanSession.scan_type == scan_type)
            if tool_name:
                query = query.where(ScanSession.tool_name == tool_name)

            # Get total count
            count_query = select(func.count()).select_from(ScanSession)
            if domain:
                escaped_domain = _escape_sql_wildcards(domain)
                count_query = count_query.where(ScanSession.domains_scanned.contains(escaped_domain))
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

    def delete_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Delete a scan session and all associated data in a single transaction.

        Args:
            scan_id: Scan ID to delete

        Returns:
            Dictionary with success status and counts of deleted records

        Raises:
            ValueError: If scan not found

        Note:
            All deletions are performed in a single transaction to ensure
            data consistency. If any deletion fails, the entire operation
            is rolled back.
        """
        with Session(self.engine) as session:
            try:
                scan = session.get(ScanSession, scan_id)

                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                # Delete associated findings
                findings_stmt = delete(Finding).where(Finding.scan_id == scan_id)
                findings_result = session.exec(findings_stmt)
                findings_deleted = findings_result.rowcount

                # Delete associated tool results
                subfinder_stmt = delete(SubfinderResult).where(SubfinderResult.scan_id == scan_id)
                subfinder_result = session.exec(subfinder_stmt)
                subfinder_deleted = subfinder_result.rowcount

                naabu_stmt = delete(NaabuResult).where(NaabuResult.scan_id == scan_id)
                naabu_result = session.exec(naabu_stmt)
                naabu_deleted = naabu_result.rowcount

                # Delete the scan session itself
                session.delete(scan)
                session.commit()

                return {
                    'success': True,
                    'scan_id': scan_id,
                    'findings_deleted': findings_deleted,
                    'tool_results_deleted': subfinder_deleted + naabu_deleted
                }

            except Exception as e:
                # Rollback transaction on any error
                session.rollback()
                raise

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
                - remediation_steps: Optional remediation steps (FIXED: was 'remediation')
                - tool_source: Tool that generated the alert (maps to detector)
                - discovered_at: Discovery timestamp
                - service_type: Detected service name (NEW: nmap integration)
                - service_version: Service version (NEW: nmap integration)
                - service_confidence: Detection confidence 0-100 (NEW: nmap integration)
                - cve_ids: JSON list of CVE IDs (NEW: vulnerability detection)
                - cvss_score: Highest CVSS score 0-10 (NEW: vulnerability detection)
                - vulnerability_description: CVE details (NEW: vulnerability detection)

        Returns:
            Dictionary with success status and count of stored alerts
        """
        # Map old alert schema to new finding schema
        findings = []
        for alert in alerts:
            # Build evidence dictionary with service and CVE data
            evidence = {}

            # Service detection data (from Phase 1)
            if alert.get('service_type'):
                evidence['service_type'] = alert.get('service_type')
            if alert.get('service_version'):
                evidence['service_version'] = alert.get('service_version')
            if alert.get('service_confidence') is not None:
                evidence['service_confidence'] = alert.get('service_confidence')

            # CVE vulnerability detection data (from Phase 3.5)
            if alert.get('cve_ids'):
                evidence['cve_ids'] = alert.get('cve_ids')  # Already JSON string
            if alert.get('cvss_score') is not None:
                evidence['cvss_score'] = alert.get('cvss_score')
            if alert.get('cvss_vector'):
                evidence['cvss_vector'] = alert.get('cvss_vector')
            if alert.get('vulnerability_description'):
                evidence['vulnerability_description'] = alert.get('vulnerability_description')

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
                'remediation': alert.get('remediation_steps', alert.get('remediation')),  # FIXED: Try both keys
                'discovered_at': alert.get('discovered_at'),
                'evidence': json.dumps(evidence) if evidence else None  # NEW: Store evidence
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

    def get_discovered_subdomains(
        self,
        domain: str,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get discovered subdomains for a domain from subfinder_results.

        This queries the actual scan results rather than the history table.

        Args:
            domain: Apex domain
            limit: Maximum number of records to return
            offset: Number of records to skip

        Returns:
            Dictionary with subdomains list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Get unique subdomains with most recent discovery time
            # Using subquery to get distinct subdomains with their latest discovery
            subquery = (
                select(
                    SubfinderResult.subdomain,
                    func.max(SubfinderResult.discovered_at).label('discovered_at')
                )
                .where(SubfinderResult.apex_domain == domain)
                .group_by(SubfinderResult.subdomain)
                .subquery()
            )

            # Get total count of unique subdomains
            count_query = select(func.count(func.distinct(SubfinderResult.subdomain))).where(
                SubfinderResult.apex_domain == domain
            )
            total_count = session.exec(count_query).one()

            # Get paginated results ordered by discovery time
            query = (
                select(subquery.c.subdomain, subquery.c.discovered_at)
                .order_by(subquery.c.discovered_at.desc())
                .offset(offset)
                .limit(limit)
            )

            results = session.exec(query).all()

            return {
                'subdomains': [
                    {'subdomain': r[0], 'first_seen': r[1]}
                    for r in results
                ],
                'total_count': total_count,
                'has_more': (offset + len(results)) < total_count,
                'limit': limit,
                'offset': offset
            }

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
        # Escape wildcards for security in LIKE queries
        escaped_domain = _escape_sql_wildcards(domain)

        with Session(self.engine) as session:
            preview = {
                'domain': domain,
                'totals': {}
            }

            # Count scan sessions
            scan_count = session.exec(
                select(func.count()).select_from(ScanSession).where(
                    ScanSession.domains_scanned.contains(escaped_domain)
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

            # Nmap and Naabu counts (use escaped domain for LIKE queries)
            nmap_count = session.exec(
                select(func.count()).select_from(NmapResult).where(
                    NmapResult.target_host.contains(escaped_domain)
                )
            ).one()
            preview['totals']['nmap_results'] = nmap_count

            naabu_count = session.exec(
                select(func.count()).select_from(NaabuResult).where(
                    NaabuResult.target_host.contains(escaped_domain)
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
        Delete domain and all associated data in a single transaction.

        Args:
            domain: Domain to delete

        Returns:
            Dictionary with counts of deleted records by category

        Note:
            All deletions are performed in a single transaction to ensure
            data consistency. If any deletion fails, the entire operation
            is rolled back.
        """
        # Escape wildcards for security in LIKE queries
        escaped_domain = _escape_sql_wildcards(domain)

        with Session(self.engine) as session:
            try:
                deleted = {}

                # Delete subdomain history
                result = session.exec(
                    delete(SubdomainHistory).where(
                        SubdomainHistory.apex_domain == domain
                    )
                )
                deleted['subdomain_history'] = result.rowcount

                # Delete findings (security alerts now stored as findings)
                # Match exact domain AND subdomains (e.g., api.example.com for example.com)
                result = session.exec(
                    delete(Finding).where(
                        or_(
                            Finding.affected_asset == domain,
                            Finding.affected_asset.endswith(f".{domain}")
                        )
                    )
                )
                deleted['findings'] = result.rowcount

                # Delete tool results
                result = session.exec(
                    delete(SubfinderResult).where(
                        SubfinderResult.apex_domain == domain
                    )
                )
                deleted['subfinder_results'] = result.rowcount

                result = session.exec(
                    delete(AmassResult).where(
                        AmassResult.apex_domain == domain
                    )
                )
                deleted['amass_results'] = result.rowcount

                # Use escaped domain for LIKE queries (contains)
                result = session.exec(
                    delete(NmapResult).where(
                        NmapResult.target_host.contains(escaped_domain)
                    )
                )
                deleted['nmap_results'] = result.rowcount

                result = session.exec(
                    delete(NaabuResult).where(
                        NaabuResult.target_host.contains(escaped_domain)
                    )
                )
                deleted['naabu_results'] = result.rowcount

                # Delete scan sessions (use escaped domain)
                result = session.exec(
                    delete(ScanSession).where(
                        ScanSession.domains_scanned.contains(escaped_domain)
                    )
                )
                deleted['scan_sessions'] = result.rowcount

                # Finally, delete the domain itself
                domain_obj = session.get(Domain, domain)
                if domain_obj:
                    session.delete(domain_obj)
                    deleted['domain'] = 1
                else:
                    deleted['domain'] = 0

                # Commit all changes in a single transaction
                session.commit()
                return deleted

            except Exception as e:
                # Rollback transaction on any error (database, validation, etc.)
                session.rollback()
                raise

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

    def store_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Store analysis findings in database with deduplication.

        Checks for existing findings with same (finding_type, affected_asset, port)
        and updates them instead of creating duplicates.

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

        Returns:
            Dictionary with counts: {'new': N, 'updated': M}
        """
        now = get_ist_now()
        new_count = 0
        updated_count = 0

        with Session(self.engine) as session:
            for finding_data in findings:
                finding_type = finding_data['finding_type']
                affected_asset = finding_data['affected_asset']
                port = finding_data.get('port')

                # Check for existing finding with same deduplication key
                query = select(Finding).where(
                    and_(
                        Finding.finding_type == finding_type,
                        Finding.affected_asset == affected_asset,
                        Finding.port == port if port is not None else Finding.port.is_(None)
                    )
                )
                existing = session.exec(query).first()

                if existing:
                    # Update existing finding
                    existing.last_seen = now
                    existing.occurrence_count += 1
                    existing.updated_at = now
                    existing.scan_id = finding_data['scan_id']  # Update to latest scan

                    # Update severity if new one is higher
                    new_severity = finding_data.get('severity', 'medium')
                    if self.SEVERITY_ORDER.get(new_severity, 0) > self.SEVERITY_ORDER.get(existing.severity, 0):
                        existing.severity = new_severity
                        existing.risk_score = finding_data.get('risk_score', existing.risk_score)

                    # Status transition: if resolved → reopen
                    if existing.status == 'resolved':
                        existing.status = 'reopened'
                        existing.reopened_at = now
                        existing.resolved_at = None  # Clear resolved timestamp

                    # Status transition: new → open (seen multiple times now)
                    elif existing.status == 'new':
                        existing.status = 'open'

                    session.add(existing)
                    updated_count += 1
                else:
                    # Create new finding with status='new' (first time discovered)
                    finding = Finding(
                        id=finding_data.get('id', str(uuid.uuid4())),
                        scan_id=finding_data['scan_id'],
                        finding_type=finding_type,
                        affected_asset=affected_asset,
                        port=port,
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
                        status='new',  # First time discovered
                        false_positive=False,
                        first_seen=now,
                        last_seen=now,
                        occurrence_count=1,
                        updated_at=now
                    )
                    session.add(finding)
                    new_count += 1

            session.commit()

        return {'new': new_count, 'updated': updated_count}

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        affected_asset: Optional[str] = None,
        min_severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieve findings with optional filters.

        Args:
            scan_id: Filter by scan ID
            affected_asset: Filter by affected asset
            min_severity: Minimum severity (critical/high/medium/low/info)
            status: Filter by status (new/open/acknowledged/resolved/reopened/false_positive)
            limit: Maximum number of findings to return
            offset: Number of findings to skip

        Returns:
            Dictionary with findings list, total count, and pagination info
        """
        with Session(self.engine) as session:
            # Build query
            query = select(Finding)

            # Apply filters
            filters = []
            if scan_id:
                filters.append(Finding.scan_id == scan_id)
            if affected_asset:
                filters.append(Finding.affected_asset == affected_asset)
            if min_severity and min_severity in self.SEVERITY_ORDER:
                min_order = self.SEVERITY_ORDER[min_severity]
                valid_severities = [s for s, o in self.SEVERITY_ORDER.items() if o >= min_order]
                filters.append(Finding.severity.in_(valid_severities))
            if status and status in self.VALID_STATUSES:
                filters.append(Finding.status == status)

            if filters:
                query = query.where(and_(*filters))

            # Get total count
            count_query = select(func.count()).select_from(Finding)
            if filters:
                count_query = count_query.where(and_(*filters))
            total_count = session.exec(count_query).one()

            # Apply pagination and ordering (highest risk first, then most recent)
            query = query.order_by(Finding.risk_score.desc(), Finding.first_seen.desc())
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

    # Valid status values for findings
    VALID_STATUSES = {'new', 'open', 'acknowledged', 'resolved', 'reopened', 'false_positive'}

    # Severity ordering for comparison (higher number = more severe)
    SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """
        Update finding status with proper lifecycle handling.

        Status lifecycle:
        - new: First time discovered (auto-set on creation)
        - open: Known issue, needs attention
        - acknowledged: Team is aware, working on it
        - resolved: Fixed/closed
        - reopened: Was resolved but detected again (auto-set)
        - false_positive: Not a real issue

        Args:
            finding_id: Finding UUID
            status: New status (new/open/acknowledged/resolved/reopened/false_positive)
            resolution_notes: Optional resolution notes

        Returns:
            True if updated, False if finding not found

        Raises:
            ValueError: If status is not valid
        """
        # Validate status
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Valid: {self.VALID_STATUSES}")

        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                return False

            now = get_ist_now()
            old_status = finding.status
            finding.status = status
            finding.updated_at = now

            # Handle status-specific logic
            if status == 'resolved':
                finding.resolved_at = now
                finding.reopened_at = None  # Clear reopen timestamp

            elif status == 'reopened':
                finding.reopened_at = now
                finding.resolved_at = None  # Clear resolved timestamp

            elif status == 'false_positive':
                finding.false_positive = True
                finding.resolved_at = now  # Also mark as resolved

            elif status in ('new', 'open', 'acknowledged'):
                # Clear resolved/reopened timestamps when going back to active states
                if old_status in ('resolved', 'false_positive'):
                    finding.reopened_at = now
                    finding.resolved_at = None

            if resolution_notes:
                finding.resolution_notes = resolution_notes

            session.add(finding)
            session.commit()
            return True

    def delete_finding(self, finding_id: str) -> bool:
        """
        Delete a finding by ID.

        Args:
            finding_id: UUID of the finding to delete

        Returns:
            True if deleted, False if finding not found
        """
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                return False

            session.delete(finding)
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
                # Severity breakdown
                'critical_findings': by_severity.get('critical', 0),
                'high_findings': by_severity.get('high', 0),
                'medium_findings': by_severity.get('medium', 0),
                'low_findings': by_severity.get('low', 0),
                'info_findings': by_severity.get('info', 0),
                # Status breakdown (full lifecycle)
                'new_findings': by_status.get('new', 0),
                'open_findings': by_status.get('open', 0),
                'acknowledged_findings': by_status.get('acknowledged', 0),
                'resolved_findings': by_status.get('resolved', 0),
                'reopened_findings': by_status.get('reopened', 0),
                'false_positives': by_status.get('false_positive', 0),
                # Aggregate counts
                'active_findings': (
                    by_status.get('new', 0) +
                    by_status.get('open', 0) +
                    by_status.get('acknowledged', 0) +
                    by_status.get('reopened', 0)
                ),
                'closed_findings': (
                    by_status.get('resolved', 0) +
                    by_status.get('false_positive', 0)
                )
            }

    # ============================================================================
    # Job Queue Management (Persistent Jobs)
    # ============================================================================

    def create_job(
        self,
        job_id: str,
        job_type: str,
        payload: Dict[str, Any],
        scan_id: Optional[str] = None,
        priority: int = 100
    ) -> Job:
        """
        Create a new job in the database.

        Jobs are persisted before being pushed to ZeroMQ to prevent
        job loss if workers crash.

        Args:
            job_id: Unique job identifier (UUID)
            job_type: Type of job (e.g., "scan", "analysis")
            payload: Job payload dictionary
            scan_id: Optional associated scan ID
            priority: Job priority (lower = higher priority)

        Returns:
            The created Job object
        """
        with Session(self.engine) as session:
            now = get_ist_now()

            job = Job(
                id=job_id,
                job_type=job_type,
                payload=json.dumps(payload),
                scan_id=scan_id,
                status='pending',
                created_at=now,
                priority=priority
            )

            session.add(job)
            session.commit()
            session.refresh(job)

            return job

    def mark_job_queued(self, job_id: str) -> bool:
        """
        Mark a job as queued (pushed to ZeroMQ).

        Args:
            job_id: Job ID to update

        Returns:
            True if updated, False if job not found
        """
        with Session(self.engine) as session:
            job = session.get(Job, job_id)
            if not job:
                return False

            job.status = 'queued'
            job.queued_at = get_ist_now()
            session.add(job)
            session.commit()
            return True

    def claim_job(self, job_id: str, worker_id: str) -> bool:
        """
        Atomically claim a job for processing.

        Uses atomic UPDATE with WHERE clause to prevent race conditions.
        Only one worker can successfully claim a job even if multiple
        workers try simultaneously.

        Args:
            job_id: Job ID to claim
            worker_id: Worker ID claiming the job

        Returns:
            True if claimed, False if job not found or already claimed
        """
        from sqlalchemy import update

        with Session(self.engine) as session:
            now = get_ist_now()

            # Atomic UPDATE with WHERE clause ensures only one worker can claim
            # The UPDATE only succeeds if status is still claimable
            stmt = (
                update(Job)
                .where(
                    and_(
                        Job.id == job_id,
                        Job.status.in_(('pending', 'queued'))
                    )
                )
                .values(
                    status='processing',
                    worker_id=worker_id,
                    started_at=now
                )
            )

            result = session.execute(stmt)
            session.commit()

            # rowcount == 1 means we successfully claimed the job
            # rowcount == 0 means job doesn't exist or was already claimed
            return result.rowcount == 1

    def complete_job(
        self,
        job_id: str,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark a job as completed or failed.

        Args:
            job_id: Job ID to complete
            success: True for completed, False for failed
            error_message: Error message if failed

        Returns:
            True if updated, False if job not found
        """
        with Session(self.engine) as session:
            job = session.get(Job, job_id)
            if not job:
                return False

            job.status = 'completed' if success else 'failed'
            job.completed_at = get_ist_now()
            if error_message:
                job.error_message = error_message[:2000]  # Truncate to field limit

            session.add(job)
            session.commit()
            return True

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get job by ID.

        Args:
            job_id: Job ID to retrieve

        Returns:
            Job dictionary or None if not found
        """
        with Session(self.engine) as session:
            job = session.get(Job, job_id)
            if job:
                return self._job_to_dict(job)
            return None

    def get_stale_jobs(self, stale_minutes: int = 30) -> List[JobDict]:
        """
        Get jobs that have been processing for too long (stale).

        These jobs likely belong to crashed workers and need recovery.

        Args:
            stale_minutes: Minutes after which a processing job is considered stale

        Returns:
            List of stale job dictionaries with keys:
            - id: str (Job UUID)
            - job_type: str
            - payload: Dict[str, Any]
            - status: str
            - scan_id: Optional[str]
            - created_at: Optional[str] (ISO format)
            - started_at: Optional[str] (ISO format)
            - worker_id: Optional[str]
            - error_message: Optional[str]
            - retry_count: int
            - priority: int
        """
        from datetime import timedelta

        with Session(self.engine) as session:
            cutoff_time = get_ist_now() - timedelta(minutes=stale_minutes)

            query = select(Job).where(
                and_(
                    Job.status == 'processing',
                    Job.started_at < cutoff_time
                )
            )

            jobs = session.exec(query).all()
            return [self._job_to_dict(j) for j in jobs]

    def get_pending_jobs(self, limit: int = 100) -> List[JobDict]:
        """
        Get pending jobs that haven't been queued yet.

        Used for recovery when ZeroMQ push failed.

        Args:
            limit: Maximum number of jobs to return

        Returns:
            List of pending job dictionaries (see JobDict for structure)
        """
        with Session(self.engine) as session:
            query = select(Job).where(
                Job.status == 'pending'
            ).order_by(Job.priority, Job.created_at).limit(limit)

            jobs = session.exec(query).all()
            return [self._job_to_dict(j) for j in jobs]

    def list_jobs(
        self,
        status: Optional[str] = None,
        job_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> JobListResult:
        """
        List jobs with optional status filter.

        Args:
            status: Filter by job status (pending, queued, processing, completed, failed, cancelled)
            job_type: Filter by job type (scan, analysis, etc.)
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip

        Returns:
            JobListResult with:
            - jobs: List[JobDict] - List of job dictionaries
            - total: int - Total count of matching jobs
            - has_more: bool - Whether more results exist
        """
        with Session(self.engine) as session:
            # Build query
            query = select(Job)
            filters = []

            if status:
                filters.append(Job.status == status)
            if job_type:
                filters.append(Job.job_type == job_type)

            if filters:
                query = query.where(and_(*filters))

            # Get total count
            count_query = select(func.count()).select_from(Job)
            if filters:
                count_query = count_query.where(and_(*filters))
            total_count = session.exec(count_query).one()

            # Apply pagination and ordering (most recent first)
            query = query.order_by(Job.created_at.desc())
            query = query.offset(offset).limit(limit)

            # Execute query
            jobs = session.exec(query).all()

            return {
                'jobs': [self._job_to_dict(j) for j in jobs],
                'total': total_count,
                'has_more': (offset + len(jobs)) < total_count,
                'limit': limit,
                'offset': offset
            }

    def retry_job(self, job_id: str) -> bool:
        """
        Reset a failed job for retry.

        Args:
            job_id: Job ID to retry

        Returns:
            True if reset for retry, False if not found or max retries exceeded
        """
        with Session(self.engine) as session:
            job = session.get(Job, job_id)
            if not job:
                return False

            if job.retry_count >= job.max_retries:
                return False

            job.status = 'pending'
            job.retry_count += 1
            job.started_at = None
            job.completed_at = None
            job.worker_id = None
            job.error_message = None

            session.add(job)
            session.commit()
            return True

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or queued job atomically.

        Uses atomic UPDATE to prevent race conditions if multiple
        requests try to cancel the same job simultaneously.

        Args:
            job_id: Job ID to cancel

        Returns:
            True if cancelled, False if not found or not cancellable
        """
        from sqlalchemy import update

        with Session(self.engine) as session:
            now = get_ist_now()

            # Atomic UPDATE ensures only one cancel succeeds
            stmt = (
                update(Job)
                .where(
                    and_(
                        Job.id == job_id,
                        Job.status.in_(('pending', 'queued'))
                    )
                )
                .values(
                    status='cancelled',
                    completed_at=now
                )
            )

            result = session.execute(stmt)
            session.commit()
            return result.rowcount == 1

    def get_job_statistics(self) -> Dict[str, int]:
        """
        Get job queue statistics.

        Returns:
            Dictionary with job counts by status
        """
        with Session(self.engine) as session:
            stats = {}

            for status in ['pending', 'queued', 'processing', 'completed', 'failed', 'cancelled']:
                count = session.exec(
                    select(func.count()).select_from(Job).where(Job.status == status)
                ).one()
                stats[status] = count

            stats['total'] = session.exec(
                select(func.count()).select_from(Job)
            ).one()

            return stats

    def cleanup_old_jobs(self, days: int = 7) -> int:
        """
        Delete completed/failed/cancelled jobs older than specified days.

        Args:
            days: Delete jobs older than this many days

        Returns:
            Number of jobs deleted
        """
        from datetime import timedelta

        with Session(self.engine) as session:
            cutoff_time = get_ist_now() - timedelta(days=days)

            result = session.exec(
                delete(Job).where(
                    and_(
                        Job.status.in_(['completed', 'failed', 'cancelled']),
                        Job.completed_at < cutoff_time
                    )
                )
            )

            session.commit()
            return result.rowcount

    def _job_to_dict(self, job: Job) -> Dict[str, Any]:
        """Convert Job object to dictionary."""
        payload = {}
        if job.payload:
            try:
                payload = json.loads(job.payload)
            except (json.JSONDecodeError, TypeError):
                payload = {}

        return {
            'id': job.id,
            'job_type': job.job_type,
            'payload': payload,
            'status': job.status,
            'scan_id': job.scan_id,
            'created_at': job.created_at.isoformat() if job.created_at else None,
            'queued_at': job.queued_at.isoformat() if job.queued_at else None,
            'started_at': job.started_at.isoformat() if job.started_at else None,
            'completed_at': job.completed_at.isoformat() if job.completed_at else None,
            'worker_id': job.worker_id,
            'error_message': job.error_message,
            'retry_count': job.retry_count,
            'max_retries': job.max_retries,
            'priority': job.priority
        }

    # ============================================================================
    # Helper Methods (Internal)
    # ============================================================================

    def _scan_to_dict(self, scan: ScanSession) -> Dict[str, Any]:
        """Convert ScanSession object to dictionary using centralized converter."""
        return ScanConverter.scan_to_dict(scan)

    def _subdomain_history_to_dict(self, history: SubdomainHistory) -> Dict[str, Any]:
        """Convert SubdomainHistory object to dictionary using centralized converter."""
        return ScanConverter.subdomain_history_to_dict(history)

    def _subfinder_result_to_dict(self, result: SubfinderResult) -> Dict[str, Any]:
        """Convert SubfinderResult object to dictionary using centralized converter."""
        return ToolResultConverter.subfinder_result_to_dict(result)

    def _amass_result_to_dict(self, result: AmassResult) -> Dict[str, Any]:
        """Convert AmassResult object to dictionary using centralized converter."""
        return ToolResultConverter.amass_result_to_dict(result)

    def _nmap_result_to_dict(self, result: NmapResult) -> Dict[str, Any]:
        """Convert NmapResult object to dictionary using centralized converter."""
        return ToolResultConverter.nmap_result_to_dict(result)

    def _naabu_result_to_dict(self, result: NaabuResult) -> Dict[str, Any]:
        """Convert NaabuResult object to dictionary using centralized converter."""
        return ToolResultConverter.naabu_result_to_dict(result)

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert Finding object to dictionary using centralized converter."""
        return FindingConverter.finding_to_dict(finding)

