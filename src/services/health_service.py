"""
Health check service.

Handles health check business logic.
"""

import logging
from typing import Dict, Any

from sqlmodel import Session, select, func

from src.data.database.sqlmodel_manager import SQLModelManager
from src.data.models import Domain
from src.api.settings import settings


logger = logging.getLogger(__name__)


class HealthCheckService:
    """Service for health check operations."""

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize health check service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

    def check_health(self) -> Dict[str, Any]:
        """
        Check system health status.

        Returns:
            Dictionary containing health status information
        """
        db_status = "connected"

        try:
            # Simple query to test database connectivity
            with Session(self.db.engine) as session:
                session.exec(select(func.count(Domain.domain))).one()
        except Exception as e:
            db_status = f"error: {str(e)}"
            logger.error(f"Database health check failed: {e}")

        return {
            'status': 'healthy',
            'version': settings.version,
            'database': db_status
        }
