"""
Scan management service.

Handles CRUD operations for scans. Workflow execution
is delegated to ScanWorkflowOrchestrator.
"""

import logging
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain
from src.utils.timezone import get_ist_now, format_datetime_iso
from src.utils.domain_helpers import extract_primary_domain
from src.services.exceptions import ScanNotFound, InvalidScanStatus
from src.services.scan_workflow_orchestrator import ScanWorkflowOrchestrator

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing scans (CRUD operations)."""

    def __init__(
        self,
        db_manager: SQLModelManager,
        enable_analysis: bool = True
    ):
        """
        Initialize scan service.

        Args:
            db_manager: Database manager instance
            enable_analysis: Enable analysis layer integration (default: True)
        """
        self.db = db_manager

        # Workflow orchestrator handles scan execution
        self._orchestrator = ScanWorkflowOrchestrator(
            db_manager=db_manager,
            enable_analysis=enable_analysis
        )

    # =========================================================================
    # Scan CRUD Operations
    # =========================================================================

    def create_scan(
        self,
        domains: List[str],
        scan_type: str = 'passive_subdomain_enum',
        tool_name: str = 'subfinder'
    ) -> Dict[str, Any]:
        """
        Create a new scan session.

        Args:
            domains: List of domains to scan
            scan_type: Type of scan to perform
            tool_name: Tool to use for scanning

        Returns:
            Dictionary containing scan session ID and metadata
        """
        # Validate all domains
        validated_domains = [validate_domain(d) for d in domains]

        # Create scan session
        scan_id = self.db.create_scan_session(
            scan_type=scan_type,
            domains=validated_domains,
            tool_name=tool_name
        )

        return {
            'success': True,
            'scan_id': scan_id,
            'domains': validated_domains,
            'scan_type': scan_type,
            'tool_name': tool_name
        }

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get status of a scan session.

        Args:
            scan_id: Scan session ID

        Returns:
            Dictionary containing scan status information

        Raises:
            ScanNotFound: If scan ID doesn't exist
        """
        scan_info = self.db.get_scan_status(scan_id)

        if not scan_info:
            raise ScanNotFound(f'Scan ID not found: {scan_id}')

        # Normalize domain field
        scan_info['domain'] = extract_primary_domain(scan_info)

        return {
            'success': True,
            'scan': scan_info
        }

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get results for a scan session.

        Args:
            scan_id: Scan session ID

        Returns:
            Dictionary containing scan results

        Raises:
            ScanNotFound: If scan ID doesn't exist
        """
        # Get scan info
        scan_info = self.db.get_scan_status(scan_id)

        if not scan_info:
            raise ScanNotFound(f'Scan ID not found: {scan_id}')

        # Get subfinder results (subdomains)
        subfinder_results = self.db.get_tool_results(
            scan_id=scan_id,
            tool_name='subfinder',
            limit=10000
        )

        subdomains = []
        for result in subfinder_results.get('results', []):
            subdomains.append({
                'subdomain': result.get('subdomain', ''),
                'ip_address': result.get('ip_address', ''),
                'discovered_at': format_datetime_iso(result.get('discovered_at'))
            })

        # Get naabu results (ports)
        naabu_results = self.db.get_tool_results(
            scan_id=scan_id,
            tool_name='naabu',
            limit=10000
        )

        ports = []
        for result in naabu_results.get('results', []):
            ports.append({
                'subdomain': result.get('target_host', ''),
                'port': result.get('port', 0),
                'protocol': result.get('protocol', 'tcp'),
                'ip': result.get('ip', ''),
                'discovered_at': format_datetime_iso(result.get('discovered_at'))
            })

        # Extract domains from scan info
        domains_scanned = scan_info.get('domains_scanned', [])
        first_domain = domains_scanned[0] if domains_scanned else ''

        return {
            'success': True,
            'scan': {
                'scan_id': scan_info['scan_id'],
                'domain': first_domain,
                'scan_type': scan_info.get('scan_type', 'passive_subdomain_enum'),
                'tool_name': scan_info.get('tool_name', 'subfinder'),
                'status': scan_info['status'],
                'start_time': format_datetime_iso(scan_info.get('start_time')),
                'end_time': format_datetime_iso(scan_info.get('end_time')),
                'findings_count': scan_info.get('findings_count', 0),
                'total_subdomains': len(subdomains),
                'total_ports': len(ports)
            },
            'subdomains': subdomains,
            'ports': ports
        }

    def list_scans(self, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        """
        List scan sessions with pagination.

        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip

        Returns:
            Dictionary containing list of scans with pagination info
        """
        result = self.db.get_scan_history(limit=limit, offset=offset)

        scans = []
        for scan in result.get('scans', []):
            domain = extract_primary_domain(scan)

            scans.append({
                'scan_id': scan.get('scan_id'),
                'scan_type': scan.get('scan_type', 'passive_subdomain_enum'),
                'tool_name': scan.get('tool_name'),
                'domain': domain,
                'status': scan.get('status'),
                'findings_count': scan.get('findings_count', 0),
                'start_time': scan.get('start_time'),
                'end_time': scan.get('end_time')
            })

        total_count = result.get('total_count', len(scans))
        return {
            'success': True,
            'scans': scans,
            'total_count': total_count,
            'has_more': (offset + limit) < total_count
        }

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update scan session status.

        Args:
            scan_id: ID of the scan to update
            status: New status (pending, running, completed, failed)
            error: Optional error message if status is failed

        Returns:
            Dictionary with update result
        """
        logger.info(f"Updating scan {scan_id} status to: {status}")
        if error:
            logger.error(f"Scan {scan_id} error: {error}")
        self.db.update_scan_status(scan_id, status)
        return {
            'success': True,
            'scan_id': scan_id,
            'status': status
        }

    def delete_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Delete a scan and all associated data.

        Args:
            scan_id: Scan ID to delete

        Returns:
            Dictionary with deletion results

        Raises:
            ScanNotFound: If scan ID doesn't exist
            InvalidScanStatus: If scan is currently running
        """
        scan_info = self.db.get_scan_status(scan_id)
        if not scan_info:
            raise ScanNotFound(f"Scan ID not found: {scan_id}")

        if scan_info.get('status') == 'running':
            raise InvalidScanStatus(
                f"Cannot delete scan {scan_id} while it is running. "
                "Cancel the scan first."
            )

        result = self.db.delete_scan(scan_id)
        logger.info(
            f"Deleted scan {scan_id}: {result.get('findings_deleted', 0)} findings, "
            f"{result.get('tool_results_deleted', 0)} tool results"
        )

        return result

    def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Cancel a pending or running scan.

        Args:
            scan_id: Scan ID to cancel

        Returns:
            Dictionary with updated scan status

        Raises:
            ScanNotFound: If scan ID doesn't exist
            InvalidScanStatus: If scan is already completed/failed/cancelled
        """
        scan_info = self.db.get_scan_status(scan_id)
        if not scan_info:
            raise ScanNotFound(f"Scan ID not found: {scan_id}")

        current_status = scan_info.get('status')

        if current_status not in ['pending', 'running']:
            raise InvalidScanStatus(
                f"Cannot cancel scan {scan_id} with status '{current_status}'. "
                "Can only cancel pending or running scans."
            )

        self.db.update_scan_status(
            scan_id,
            'cancelled',
            end_time=get_ist_now()
        )

        logger.info(f"Cancelled scan {scan_id} (was {current_status})")
        return self.get_scan_status(scan_id)

    def retry_scan(
        self,
        scan_id: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Retry a failed scan by creating a new scan with the same domain.

        Args:
            scan_id: ID of the failed scan to retry
            timeout: Optional timeout override for the new scan

        Returns:
            Dictionary with new scan information

        Raises:
            ScanNotFound: If scan ID doesn't exist
            InvalidScanStatus: If scan is not in failed status
        """
        scan_info = self.db.get_scan_status(scan_id)
        if not scan_info:
            raise ScanNotFound(f"Scan ID not found: {scan_id}")

        current_status = scan_info.get('status')

        if current_status != 'failed':
            raise InvalidScanStatus(
                f"Cannot retry scan {scan_id} with status '{current_status}'. "
                "Can only retry failed scans."
            )

        domain = extract_primary_domain(scan_info)
        if domain == 'unknown':
            raise ValueError(f"Could not determine domain for scan {scan_id}")

        new_scan = self.create_scan(domains=[domain])

        logger.info(f"Retrying failed scan {scan_id} as new scan {new_scan['scan_id']}")

        return {
            'success': True,
            'original_scan_id': scan_id,
            'new_scan_id': new_scan['scan_id'],
            'domain': domain,
            'status': 'pending',
            'timeout': timeout
        }

    # =========================================================================
    # Workflow Execution (Delegated to Orchestrator)
    # =========================================================================

    def execute_scan(
        self,
        domain: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a complete scan workflow for a domain.

        Creates a scan session and executes the full workflow.

        Args:
            domain: Domain to scan
            timeout: Optional timeout in seconds

        Returns:
            Dictionary containing scan results
        """
        domain = validate_domain(domain)

        # Create scan session
        scan_id = self.db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=[domain],
            tool_name='subfinder'
        )

        try:
            # Delegate to orchestrator
            result = self._orchestrator.execute_workflow(scan_id, domain, timeout)

            # Update scan status
            self.db.update_scan_status(
                scan_id,
                'completed',
                end_time=get_ist_now(),
                findings_count=result.get('findings_count', 0)
            )

            return result

        except Exception as e:
            self.db.update_scan_status(scan_id, 'failed', end_time=get_ist_now())
            raise

    def execute_scan_workflow(
        self,
        scan_id: str,
        domain: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute scan workflow for an existing scan session.

        Called by worker after scan is created via API.

        Args:
            scan_id: Existing scan session ID
            domain: Domain to scan
            timeout: Optional timeout in seconds

        Returns:
            Dictionary containing scan results
        """
        # Delegate to orchestrator
        return self._orchestrator.execute_workflow(scan_id, domain, timeout)

    def execute_scan_async(
        self,
        domain: str,
        timeout: Optional[int] = None,
        save: bool = True
    ) -> Dict[str, Any]:
        """
        Create scan session for async execution.

        Args:
            domain: Domain to scan
            timeout: Optional timeout in seconds
            save: Whether to save results to database

        Returns:
            Dictionary containing scan session information
        """
        scan_id = self.db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=[domain],
            tool_name='subfinder'
        )

        logger.info(f"Created async scan session {scan_id} for domain: {domain}")

        return {
            'success': True,
            'scan': {
                'scan_id': scan_id,
                'domain': domain,
                'scan_type': 'passive_subdomain_enum',
                'tool_name': 'subfinder',
                'status': 'pending',
                'findings_count': 0
            }
        }

    def trigger_analysis(self, scan_id: str) -> Dict[str, Any]:
        """
        Trigger analysis on a completed scan.

        Args:
            scan_id: ID of the scan to analyze

        Returns:
            Dictionary containing analysis status

        Raises:
            ScanNotFound: If scan not found
            InvalidScanStatus: If scan not completed
        """
        scan_data = self.get_scan_status(scan_id)

        if not scan_data.get('scan'):
            raise ScanNotFound(f"Scan not found: {scan_id}")

        status = scan_data['scan'].get('status')
        if status not in ['completed', 'finished']:
            raise InvalidScanStatus(
                f"Scan must be completed before analysis. Current status: {status}. "
                f"Required status: completed or finished"
            )

        logger.info(f"Analysis triggered for scan: {scan_id}")

        return {
            'success': True,
            'scan_id': scan_id,
            'status': 'analyzing'
        }

