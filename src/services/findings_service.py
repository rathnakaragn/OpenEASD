"""
Findings Service for OpenEASD.

Provides business logic for finding management operations.
Used by both API and CLI layers to ensure consistent behavior.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import List, Dict, Any, Optional
import logging

from src.data.database.sqlmodel_manager import SQLModelManager


logger = logging.getLogger(__name__)


class FindingNotFound(Exception):
    """Raised when a finding is not found."""
    pass


class InvalidFindingStatus(Exception):
    """Raised when an invalid finding status is provided."""
    pass


VALID_STATUSES = ['open', 'acknowledged', 'resolved', 'false_positive']
VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']


class FindingsService:
    """
    Service layer for finding operations.

    Provides business logic abstraction between API/CLI and database layer.
    Ensures consistent behavior for finding management across all interfaces.
    """

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize FindingsService.

        Args:
            db_manager: SQLModelManager instance for database operations
        """
        self.db = db_manager

    def list_findings(
        self,
        scan_id: Optional[str] = None,
        affected_asset: Optional[str] = None,
        min_severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        List findings with optional filters.

        Args:
            scan_id: Filter by scan ID
            affected_asset: Filter by affected asset (domain/subdomain/IP)
            min_severity: Minimum severity level (critical/high/medium/low/info)
            status: Filter by status (open/acknowledged/resolved/false_positive)
            limit: Maximum results to return (1-1000)
            offset: Number of results to skip for pagination

        Returns:
            Dict with 'findings' list and 'pagination' metadata
        """
        # Validate min_severity if provided
        if min_severity and min_severity not in VALID_SEVERITIES:
            logger.warning(f"Invalid severity filter: {min_severity}")
            min_severity = None

        # Validate status if provided
        if status and status not in VALID_STATUSES:
            logger.warning(f"Invalid status filter: {status}")
            status = None

        result = self.db.get_findings(
            scan_id=scan_id,
            affected_asset=affected_asset,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )

        logger.debug(
            f"Listed {len(result.get('findings', []))} findings "
            f"(scan_id={scan_id}, asset={affected_asset}, severity>={min_severity})"
        )

        return result

    def get_finding(self, finding_id: str) -> Dict[str, Any]:
        """
        Get a specific finding by ID.

        Args:
            finding_id: UUID of the finding

        Returns:
            Finding details as dict

        Raises:
            FindingNotFound: If finding doesn't exist
        """
        finding = self.db.get_finding_by_id(finding_id)

        if not finding:
            logger.info(f"Finding not found: {finding_id}")
            raise FindingNotFound(f"Finding {finding_id} not found")

        return finding

    def update_status(
        self,
        finding_id: str,
        status: str,
        resolution_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update finding status.

        Args:
            finding_id: UUID of the finding
            status: New status (open/acknowledged/resolved/false_positive)
            resolution_notes: Optional notes about the resolution

        Returns:
            Dict with success status and message

        Raises:
            FindingNotFound: If finding doesn't exist
            InvalidFindingStatus: If status is not valid
        """
        # Validate status
        if status not in VALID_STATUSES:
            raise InvalidFindingStatus(
                f"Invalid status: {status}. "
                f"Must be one of: {', '.join(VALID_STATUSES)}"
            )

        # Check if finding exists
        existing = self.db.get_finding_by_id(finding_id)
        if not existing:
            raise FindingNotFound(f"Finding {finding_id} not found")

        # Update status
        success = self.db.update_finding_status(
            finding_id=finding_id,
            status=status,
            resolution_notes=resolution_notes
        )

        if success:
            logger.info(
                f"Finding {finding_id} status updated: "
                f"{existing.get('status', 'unknown')} -> {status}"
            )
            return {
                "success": True,
                "message": f"Finding {finding_id} status updated to {status}",
                "finding_id": finding_id,
                "new_status": status
            }
        else:
            logger.error(f"Failed to update finding {finding_id} status")
            return {
                "success": False,
                "message": f"Failed to update finding {finding_id}",
                "finding_id": finding_id
            }

    def get_statistics(
        self,
        scan_id: Optional[str] = None,
        affected_asset: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get finding statistics.

        Args:
            scan_id: Filter statistics for a specific scan
            affected_asset: Filter statistics for a specific asset

        Returns:
            Dict with severity breakdown, status counts, and risk metrics
        """
        stats = self.db.get_findings_statistics(
            scan_id=scan_id,
            affected_asset=affected_asset
        )

        logger.debug(
            f"Retrieved statistics (scan_id={scan_id}, asset={affected_asset}): "
            f"{stats.get('total', 0)} total findings"
        )

        return stats

    def get_findings_by_scan(
        self,
        scan_id: str,
        min_severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get all findings for a specific scan.

        Args:
            scan_id: UUID of the scan session
            min_severity: Minimum severity level filter
            limit: Maximum results to return
            offset: Number of results to skip

        Returns:
            Dict with 'findings' list and 'pagination' metadata
        """
        return self.list_findings(
            scan_id=scan_id,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )

    def get_findings_by_asset(
        self,
        asset_name: str,
        min_severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get all findings for a specific asset.

        Args:
            asset_name: Domain, subdomain, or IP address
            min_severity: Minimum severity level filter
            limit: Maximum results to return
            offset: Number of results to skip

        Returns:
            Dict with 'findings' list and 'pagination' metadata
        """
        return self.list_findings(
            affected_asset=asset_name,
            min_severity=min_severity,
            limit=limit,
            offset=offset
        )


__all__ = ['FindingsService', 'FindingNotFound', 'InvalidFindingStatus']
