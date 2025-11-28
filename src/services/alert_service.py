"""
Security alert management service.

Handles business logic for security alert operations.
Now uses the Analysis Layer's AlertManagementService for unified alert/finding management.
"""

from typing import Dict, Any, Optional, Union
from datetime import datetime
from src.data.database.sqlmodel_manager import SQLModelManager
from src.analysis.alert_service import AlertManagementService


class AlertService:
    """
    Service for managing security alerts.

    This service now delegates to the Analysis Layer's AlertManagementService
    for all alert operations, providing a consistent interface while leveraging
    advanced features like risk scoring and finding management.
    """

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize alert service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        # Initialize analysis layer alert service
        self.alert_mgmt_service = AlertManagementService(db_manager)

    def _format_datetime(self, dt: Optional[Union[datetime, str]]) -> str:
        """
        Convert datetime object to ISO format string.

        Args:
            dt: Datetime object or string

        Returns:
            ISO format datetime string
        """
        if isinstance(dt, datetime):
            return dt.isoformat()
        return str(dt) if dt else ''

    def list_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        domain: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List security alerts with optional filtering.

        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (info, low, medium, high, critical)
            domain: Filter by domain
            min_severity: Minimum severity level to include

        Returns:
            Dictionary containing alerts list
        """
        # Use analysis layer alert management service
        result = self.alert_mgmt_service.get_alerts(
            limit=limit,
            severity=severity,
            domain=domain,
            min_severity=min_severity
        )

        # Return in expected format (already formatted by AlertManagementService)
        return {
            'success': True,
            'alerts': result.get('alerts', []),
            'total': result.get('total', 0)
        }

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Get details of a specific alert.

        Args:
            alert_id: Alert ID

        Returns:
            Dictionary containing alert details

        Raises:
            ValueError: If alert doesn't exist
        """
        # Use analysis layer alert management service
        result = self.alert_mgmt_service.get_alert_by_id(alert_id)

        return {
            'success': True,
            'alert': result.get('alert')
        }

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics.

        Returns:
            Dictionary containing alert statistics by severity, type, detector, etc.
        """
        # Use analysis layer alert management service
        stats = self.alert_mgmt_service.get_alert_statistics()

        return {
            'success': True,
            'statistics': stats
        }
