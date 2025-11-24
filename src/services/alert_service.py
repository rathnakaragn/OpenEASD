"""
Security alert management service.

Handles business logic for security alert operations.
"""

from typing import List, Dict, Any, Optional
from src.data.database.duckdb_manager import DuckDBManager


class AlertService:
    """Service for managing security alerts."""

    def __init__(self, db_manager: DuckDBManager):
        """
        Initialize alert service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

    def list_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List security alerts with optional filtering.

        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (info, low, medium, high, critical)
            domain: Filter by domain

        Returns:
            Dictionary containing alerts list
        """
        query = """
            SELECT
                alert_id,
                scan_id,
                domain,
                vulnerability_type,
                severity,
                description,
                tool_source,
                discovered_at,
                status
            FROM security_alerts
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if domain:
            query += " AND domain = ?"
            params.append(domain)

        query += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)

        result = self.db.connection.execute(query, params).fetchall()

        alerts = []
        for row in result:
            alerts.append({
                'alert_id': row[0],
                'scan_id': row[1],
                'domain': row[2],
                'vulnerability_type': row[3],
                'severity': row[4],
                'description': row[5],
                'tool_source': row[6],
                'discovered_at': row[7].isoformat() if row[7] else '',
                'status': row[8] if len(row) > 8 else 'open'
            })

        return {
            'success': True,
            'alerts': alerts,
            'total': len(alerts)
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
        result = self.db.connection.execute("""
            SELECT
                alert_id,
                scan_id,
                domain,
                vulnerability_type,
                severity,
                description,
                tool_source,
                discovered_at,
                status
            FROM security_alerts
            WHERE alert_id = ?
        """, [alert_id]).fetchone()

        if not result:
            raise ValueError(f'Alert not found: {alert_id}')

        alert = {
            'alert_id': result[0],
            'scan_id': result[1],
            'domain': result[2],
            'vulnerability_type': result[3],
            'severity': result[4],
            'description': result[5],
            'tool_source': result[6],
            'discovered_at': result[7].isoformat() if result[7] else '',
            'status': result[8] if len(result) > 8 else 'open'
        }

        return {
            'success': True,
            'alert': alert
        }

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics.

        Returns:
            Dictionary containing alert statistics by severity, type, etc.
        """
        # Count by severity
        severity_counts = self.db.connection.execute("""
            SELECT severity, COUNT(*) as count
            FROM security_alerts
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
        """).fetchall()

        # Count by type
        type_counts = self.db.connection.execute("""
            SELECT vulnerability_type, COUNT(*) as count
            FROM security_alerts
            GROUP BY vulnerability_type
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()

        # Count by tool
        tool_counts = self.db.connection.execute("""
            SELECT tool_source, COUNT(*) as count
            FROM security_alerts
            GROUP BY tool_source
            ORDER BY count DESC
        """).fetchall()

        # Total alerts
        total = self.db.connection.execute("""
            SELECT COUNT(*) FROM security_alerts
        """).fetchone()[0]

        return {
            'success': True,
            'statistics': {
                'total': total,
                'by_severity': {row[0]: row[1] for row in severity_counts},
                'by_type': {row[0]: row[1] for row in type_counts},
                'by_tool': {row[0]: row[1] for row in tool_counts}
            }
        }
