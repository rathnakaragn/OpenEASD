"""
OpenEASD Recon Layer - Abstract Tool Interface
6-Layer Architecture - Recon Layer

Abstract base class for all security reconnaissance tools.
Defines the interface for tool execution, output parsing, and result handling.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
import subprocess
import json


class ToolStatus(str, Enum):
    """Tool execution status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ToolType(str, Enum):
    """Security tool type enumeration."""
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    DOMAIN_INTELLIGENCE = "domain_intelligence"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    WEB_SCANNING = "web_scanning"


@dataclass
class ReconResult:
    """
    Standardized result structure for all reconnaissance tools.
    """
    tool_name: str
    tool_version: Optional[str]
    target: str
    status: ToolStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Results data
    raw_output: str = ""
    parsed_data: Dict[str, Any] = None
    assets_discovered: List[Dict[str, Any]] = None
    
    # Error handling
    error_message: Optional[str] = None
    return_code: Optional[int] = None
    
    # Performance metrics
    command_line: Optional[str] = None
    resource_usage: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.parsed_data is None:
            self.parsed_data = {}
        if self.assets_discovered is None:
            self.assets_discovered = []
        if self.resource_usage is None:
            self.resource_usage = {}
            
        # Calculate duration if both times are available
        if self.end_time and self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def is_success(self) -> bool:
        """Check if the tool execution was successful."""
        return self.status == ToolStatus.COMPLETED and self.return_code == 0

    def get_asset_count(self) -> int:
        """Get the number of assets discovered."""
        return len(self.assets_discovered)

    def add_asset(self, asset: Dict[str, Any]) -> None:
        """Add a discovered asset to the results."""
        if asset not in self.assets_discovered:
            self.assets_discovered.append(asset)

    def set_error(self, error_message: str, return_code: Optional[int] = None) -> None:
        """Set error information for the result."""
        self.error_message = error_message
        self.status = ToolStatus.FAILED
        if return_code is not None:
            self.return_code = return_code

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "target": self.target,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "raw_output": self.raw_output,
            "parsed_data": self.parsed_data,
            "assets_discovered": self.assets_discovered,
            "error_message": self.error_message,
            "return_code": self.return_code,
            "command_line": self.command_line,
            "resource_usage": self.resource_usage
        }


class ReconTool(ABC):
    """
    Abstract base class for all reconnaissance tools.
    
    Provides common functionality for:
    - Tool execution with subprocess management
    - Async operations with timeout support
    - Output parsing and standardization
    - Error handling and recovery
    - Progress tracking and logging
    """
    
    def __init__(
        self,
        tool_name: str,
        tool_type: ToolType,
        executable_path: Optional[str] = None,
        default_timeout: int = 300,
        max_retries: int = 3
    ):
        """
        Initialize the reconnaissance tool.
        
        Args:
            tool_name: Name of the security tool
            tool_type: Type of reconnaissance tool
            executable_path: Path to tool executable (None for auto-detection)
            default_timeout: Default execution timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.tool_name = tool_name
        self.tool_type = tool_type
        self.executable_path = executable_path
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        
        # Logger for this tool
        self.logger = logging.getLogger(f"{__name__}.{tool_name}")
        
        # Tool validation
        self._validated = False
        self._tool_version = None

    @abstractmethod
    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None
    ) -> ReconResult:
        """
        Execute the reconnaissance tool against a target.
        
        Args:
            target: Target domain, IP, or other identifier
            options: Tool-specific options and parameters
            timeout: Execution timeout in seconds
            
        Returns:
            ReconResult containing execution results and discovered assets
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse tool output into standardized format.
        
        Args:
            raw_output: Raw tool output string
            
        Returns:
            Parsed data dictionary with standardized fields
        """
        pass

    @abstractmethod
    def validate_installation(self) -> bool:
        """
        Validate that the tool is properly installed and accessible.
        
        Returns:
            True if tool is available and functional
        """
        pass

    async def get_tool_version(self) -> Optional[str]:
        """
        Get the version of the installed tool.
        
        Returns:
            Tool version string or None if unavailable
        """
        if self._tool_version:
            return self._tool_version
            
        try:
            # Try common version flags
            version_commands = ["--version", "-version", "-v", "version"]
            
            for version_flag in version_commands:
                try:
                    result = await self._execute_command([version_flag], timeout=10)
                    if result.return_code == 0 and result.raw_output:
                        version = self._extract_version(result.raw_output)
                        if version:
                            self._tool_version = version
                            return version
                except:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Failed to get version for {self.tool_name}: {e}")
            
        return None

    def _extract_version(self, output: str) -> Optional[str]:
        """
        Extract version string from tool output.
        Override in subclasses for tool-specific parsing.
        """
        import re
        
        # Common version patterns
        patterns = [
            r'v?(\d+\.\d+\.\d+)',
            r'version\s+v?(\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output.lower())
            if match:
                return match.group(1)
        
        return None

    async def _execute_command(
        self,
        args: List[str],
        target: Optional[str] = None,
        timeout: Optional[int] = None,
        input_data: Optional[str] = None
    ) -> ReconResult:
        """
        Execute a command with the tool.
        
        Args:
            args: Command line arguments
            target: Target for the scan
            timeout: Command timeout in seconds
            input_data: Data to send to stdin
            
        Returns:
            ReconResult with execution results
        """
        timeout = timeout or self.default_timeout
        start_time = datetime.utcnow()
        
        # Build command
        if not self.executable_path:
            executable = self.tool_name.lower()
        else:
            executable = self.executable_path
            
        command = [executable] + args
        command_str = " ".join(command)
        
        # Create result object
        result = ReconResult(
            tool_name=self.tool_name,
            tool_version=await self.get_tool_version(),
            target=target or "unknown",
            status=ToolStatus.RUNNING,
            start_time=start_time,
            command_line=command_str
        )
        
        self.logger.info(f"Executing: {command_str}")
        
        try:
            # Execute command asynchronously
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None
            )
            
            # Wait for completion with timeout
            try:
                if input_data:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input_data.encode()),
                        timeout=timeout
                    )
                else:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout
                    )
                    
                result.return_code = process.returncode
                
            except asyncio.TimeoutError:
                self.logger.warning(f"Command timed out after {timeout} seconds")
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
                    
                result.status = ToolStatus.TIMEOUT
                result.error_message = f"Command timed out after {timeout} seconds"
                result.return_code = -1
                
            # Process output
            result.end_time = datetime.utcnow()
            result.raw_output = stdout.decode('utf-8', errors='ignore') if stdout else ""
            
            if stderr:
                stderr_text = stderr.decode('utf-8', errors='ignore')
                if stderr_text.strip():
                    self.logger.debug(f"Tool stderr: {stderr_text}")
                    
            # Set final status
            if result.status == ToolStatus.RUNNING:
                if result.return_code == 0:
                    result.status = ToolStatus.COMPLETED
                else:
                    result.status = ToolStatus.FAILED
                    if not result.error_message:
                        result.error_message = f"Tool exited with code {result.return_code}"
                        
        except FileNotFoundError:
            error_msg = f"Tool executable not found: {executable}"
            self.logger.error(error_msg)
            result.set_error(error_msg, -1)
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            error_msg = f"Command execution failed: {str(e)}"
            self.logger.error(error_msg)
            result.set_error(error_msg, -1)
            result.end_time = datetime.utcnow()
            
        return result

    def _find_executable(self, tool_names: List[str]) -> Optional[str]:
        """
        Find executable for the tool in system PATH.
        
        Args:
            tool_names: List of possible executable names
            
        Returns:
            Full path to executable or None if not found
        """
        import shutil
        
        for name in tool_names:
            path = shutil.which(name)
            if path:
                return path
                
        return None

    def _validate_target(self, target: str) -> bool:
        """
        Validate that the target is in acceptable format.
        Override in subclasses for specific validation.
        """
        if not target or not isinstance(target, str):
            return False
            
        target = target.strip()
        if not target:
            return False
            
        return True

    def _sanitize_target(self, target: str) -> str:
        """
        Sanitize target input to prevent command injection.
        """
        import re
        
        # Remove any shell metacharacters
        sanitized = re.sub(r'[;&|`$(){}[\]<>]', '', target.strip())
        
        # Remove excessive whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized

    async def execute_with_retry(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None
    ) -> ReconResult:
        """
        Execute tool with automatic retry on failure.
        
        Args:
            target: Target for reconnaissance
            options: Tool-specific options
            timeout: Execution timeout
            max_retries: Maximum retry attempts
            
        Returns:
            ReconResult from successful execution or final failure
        """
        max_retries = max_retries or self.max_retries
        last_result = None
        
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    self.logger.info(f"Retry attempt {attempt}/{max_retries} for {target}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                result = await self.execute(target, options, timeout)
                
                if result.is_success():
                    if attempt > 0:
                        self.logger.info(f"Success on retry attempt {attempt}")
                    return result
                    
                last_result = result
                
            except Exception as e:
                self.logger.warning(f"Attempt {attempt} failed: {e}")
                if attempt == max_retries:
                    # Create error result for final failure
                    result = ReconResult(
                        tool_name=self.tool_name,
                        tool_version=await self.get_tool_version(),
                        target=target,
                        status=ToolStatus.FAILED,
                        start_time=datetime.utcnow(),
                        end_time=datetime.utcnow()
                    )
                    result.set_error(f"All retry attempts failed. Last error: {str(e)}")
                    return result
                    
        return last_result or ReconResult(
            tool_name=self.tool_name,
            tool_version=await self.get_tool_version(),
            target=target,
            status=ToolStatus.FAILED,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            error_message="Max retries exceeded"
        )