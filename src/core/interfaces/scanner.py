"""
Security Scanner Interfaces for OpenEASD.

Abstract base classes defining contracts for security scanning operations.
These interfaces enable modular design and easy testing.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class SecurityTool(ABC):
    """Abstract interface for individual security tools."""
    
    @abstractmethod
    async def execute(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Execute the security tool against targets.
        
        Args:
            targets: List of domains, IPs, or URLs to scan
            **kwargs: Tool-specific configuration options
            
        Returns:
            Dictionary with results and metadata
        """
        pass
    
    @abstractmethod
    def get_tool_info(self) -> Dict[str, str]:
        """
        Get information about this security tool.
        
        Returns:
            Dictionary with tool name, version, description
        """
        pass


class SecurityScanner(ABC):
    """Abstract interface for security scanner implementations."""
    
    @abstractmethod
    async def scan_domains(self, domains: List[str], scan_type: str = "full") -> List[Dict[str, Any]]:
        """
        Execute comprehensive security scan on domains.
        
        Args:
            domains: List of domains to scan
            scan_type: Type of scan (full, incremental, targeted)
            
        Returns:
            List of security findings/alerts
        """
        pass
    
    @abstractmethod
    async def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get progress information for an ongoing scan.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            Progress information or None if scan not found
        """
        pass
    
    @abstractmethod
    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel an ongoing scan.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            True if successfully cancelled, False otherwise
        """
        pass
    
    @abstractmethod
    def get_supported_scan_types(self) -> List[str]:
        """
        Get list of supported scan types.
        
        Returns:
            List of scan type identifiers
        """
        pass