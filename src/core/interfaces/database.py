"""
Database Manager Interface for OpenEASD.

Abstract base class defining the contract for database operations.
This interface enables easy swapping of database implementations.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime


class DatabaseManager(ABC):
    """Abstract database manager interface."""
    
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the database connection and create tables if needed."""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the database connection."""
        pass
    
    # Domain Management
    @abstractmethod
    def add_domain(self, domain: str, is_primary: bool = False,
                   domain_type: str = 'apex',
                   notes: Optional[str] = None,
                   tags: Optional[List[str]] = None,
                   contact_email: Optional[str] = None,
                   scan_frequency: Optional[str] = None,
                   active_scan_enabled: bool = True) -> Dict[str, Any]:
        """Add a domain to tracking with optional metadata."""
        pass
    
    @abstractmethod
    def get_domains(self, limit: int = 20, offset: int = 0,
                    domain_type: Optional[str] = None,
                    primary_only: bool = False,
                    domain_name: Optional[str] = None) -> Dict[str, Any]:
        """Get paginated list of domains with optional filters."""
        pass
    
    @abstractmethod
    def delete_domain(self, domain: str) -> bool:
        """Remove a domain from tracking."""
        pass
    
    @abstractmethod
    def domain_exists(self, domain: str) -> bool:
        """Check if domain exists in database."""
        pass
    
    # Scan Management
    @abstractmethod
    def create_scan_session(self, scan_type: str, domains: List[str],
                           tool_name: Optional[str] = None) -> str:
        """Create a new scan session and return scan_id."""
        pass
    
    @abstractmethod
    def update_scan_status(self, scan_id: str, status: str, 
                                end_time: Optional[datetime] = None,
                                findings_count: Optional[int] = None) -> None:
        """Update scan session status."""
        pass
    
    @abstractmethod
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session information."""
        pass
    
    # Security Alerts
    @abstractmethod
    def store_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Store security alerts from scan results."""
        pass
    
    @abstractmethod
    def get_alerts(self, limit: int = 50, offset: int = 0, 
                        severity_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get paginated security alerts with optional severity filtering."""
        pass
    
    # System Metrics
    @abstractmethod
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics and performance data."""
        pass
    
    @abstractmethod
    def get_health_status(self) -> Dict[str, bool]:
        """Get database health status."""
        pass