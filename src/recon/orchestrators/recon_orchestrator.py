"""
OpenEASD Recon Layer - Reconnaissance Orchestrator
6-Layer Architecture - Recon Layer

Main orchestrator for coordinating multiple reconnaissance tools.
Manages tool execution, data collection, and workflow coordination.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable
import uuid

from ..interfaces.tool import ReconTool, ReconResult, ToolStatus, ToolType
from ..collectors.data_collector import DataCollector
from ..modules.subfinder.runner import SubfinderRunner
from ..modules.nmap.runner import NmapRunner
from ..modules.naabu.runner import NaabuRunner
from ..modules.whois.runner import WhoisRunner
from ...db.database.duckdb_manager import DuckDBManager


class WorkflowPhase(str, Enum):
    """Reconnaissance workflow phases."""
    INITIALIZATION = "initialization"
    DOMAIN_INTELLIGENCE = "domain_intelligence"
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    ANALYSIS = "analysis"
    FINALIZATION = "finalization"


class OrchestratorStatus(str, Enum):
    """Orchestrator execution status."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReconOrchestrator:
    """
    Main orchestrator for reconnaissance operations.
    
    Features:
    - Multi-tool coordination and sequencing
    - Parallel and sequential execution modes
    - Progress tracking and status reporting
    - Error handling and recovery
    - Rate limiting and throttling
    - Data collection and storage
    - Workflow customization
    """
    
    def __init__(
        self,
        database_manager: Optional[DuckDBManager] = None,
        data_collector: Optional[DataCollector] = None,
        max_concurrent_tools: int = 3,
        default_timeout: int = 1800,  # 30 minutes
        enable_rate_limiting: bool = True
    ):
        """
        Initialize the reconnaissance orchestrator.
        
        Args:
            database_manager: Database manager for persistence
            data_collector: Data collector for storing results
            max_concurrent_tools: Maximum number of concurrent tools
            default_timeout: Default timeout for tool execution
            enable_rate_limiting: Enable rate limiting between tools
        """
        self.database_manager = database_manager
        self.data_collector = data_collector or DataCollector(database_manager)
        self.max_concurrent_tools = max_concurrent_tools
        self.default_timeout = default_timeout
        self.enable_rate_limiting = enable_rate_limiting
        
        # Logger
        self.logger = logging.getLogger(f"{__name__}.ReconOrchestrator")
        
        # Tool registry
        self._tools: Dict[str, ReconTool] = {}
        self._initialize_tools()
        
        # Orchestrator state
        self.status = OrchestratorStatus.IDLE
        self.current_scan_id: Optional[str] = None
        self.current_targets: Set[str] = set()
        
        # Execution tracking
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._completed_tasks: Dict[str, ReconResult] = {}
        self._failed_tasks: Dict[str, Exception] = {}
        self._workflow_config: Dict[str, Any] = {}
        
        # Progress tracking
        self._progress_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._phase_progress: Dict[WorkflowPhase, Dict[str, Any]] = {}
        
        # Performance metrics
        self._execution_metrics = {
            "scans_completed": 0,
            "tools_executed": 0,
            "total_execution_time": 0.0,
            "average_tool_time": 0.0,
            "error_rate": 0.0
        }

    def _initialize_tools(self) -> None:
        """Initialize available reconnaissance tools."""
        try:
            # Initialize tools with error handling
            tool_configs = [
                ("subfinder", SubfinderRunner),
                ("naabu", NaabuRunner),
                ("nmap", NmapRunner),
                ("whois", WhoisRunner)
            ]
            
            for tool_name, tool_class in tool_configs:
                try:
                    tool_instance = tool_class()
                    if tool_instance.validate_installation():
                        self._tools[tool_name] = tool_instance
                        self.logger.info(f"Initialized tool: {tool_name}")
                    else:
                        self.logger.warning(f"Tool {tool_name} not available or not properly installed")
                        
                except Exception as e:
                    self.logger.error(f"Failed to initialize tool {tool_name}: {e}")
            
            self.logger.info(f"Initialized {len(self._tools)} reconnaissance tools")
            
        except Exception as e:
            self.logger.error(f"Tool initialization failed: {e}")

    async def execute_reconnaissance(
        self,
        targets: List[str],
        workflow_config: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive reconnaissance against target domains.
        
        Args:
            targets: List of target domains/IPs
            workflow_config: Workflow configuration options
            scan_id: Scan session identifier
            
        Returns:
            Comprehensive scan results
        """
        # Generate scan ID if not provided
        if not scan_id:
            scan_id = str(uuid.uuid4())
        
        self.current_scan_id = scan_id
        self.current_targets = set(targets)
        self._workflow_config = workflow_config or {}
        
        scan_start_time = datetime.utcnow()
        
        try:
            self.status = OrchestratorStatus.RUNNING
            self.logger.info(f"Starting reconnaissance scan {scan_id} for {len(targets)} targets")
            
            # Initialize scan session in database
            if self.database_manager:
                await self._initialize_scan_session(scan_id, targets)
            
            # Execute workflow phases
            results = await self._execute_workflow(targets, scan_id)
            
            # Finalize and analyze results
            final_results = await self._finalize_scan(scan_id, results, scan_start_time)
            
            self.status = OrchestratorStatus.COMPLETED
            self.logger.info(f"Reconnaissance scan {scan_id} completed successfully")
            
            return final_results
            
        except Exception as e:
            self.status = OrchestratorStatus.FAILED
            self.logger.error(f"Reconnaissance scan {scan_id} failed: {e}")
            
            # Return partial results
            return {
                "scan_id": scan_id,
                "status": "failed",
                "error": str(e),
                "partial_results": self._get_partial_results(),
                "execution_time": (datetime.utcnow() - scan_start_time).total_seconds()
            }
        
        finally:
            # Cleanup
            await self._cleanup_scan(scan_id)

    async def _execute_workflow(
        self,
        targets: List[str],
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Execute the complete reconnaissance workflow.
        
        Args:
            targets: Target domains/IPs
            scan_id: Scan session ID
            
        Returns:
            Workflow results
        """
        workflow_results = {
            "phases": {},
            "assets_discovered": [],
            "vulnerabilities": [],
            "intelligence": {},
            "performance_metrics": {}
        }
        
        # Define workflow phases with dependencies
        workflow_phases = [
            {
                "phase": WorkflowPhase.DOMAIN_INTELLIGENCE,
                "tools": ["whois"],
                "parallel": True,
                "dependencies": []
            },
            {
                "phase": WorkflowPhase.SUBDOMAIN_DISCOVERY,
                "tools": ["subfinder"],
                "parallel": True,
                "dependencies": []
            },
            {
                "phase": WorkflowPhase.PORT_SCANNING,
                "tools": ["naabu"],
                "parallel": True,
                "dependencies": [WorkflowPhase.SUBDOMAIN_DISCOVERY]
            },
            {
                "phase": WorkflowPhase.SERVICE_DETECTION,
                "tools": ["nmap"],
                "parallel": True,
                "dependencies": [WorkflowPhase.PORT_SCANNING]
            }
        ]
        
        # Execute phases in order
        for phase_config in workflow_phases:
            phase = phase_config["phase"]
            
            # Check dependencies
            await self._wait_for_dependencies(phase_config["dependencies"])
            
            # Execute phase
            phase_results = await self._execute_phase(
                phase,
                targets,
                scan_id,
                phase_config
            )
            
            workflow_results["phases"][phase.value] = phase_results
            
            # Update targets based on discovered assets
            if phase == WorkflowPhase.SUBDOMAIN_DISCOVERY:
                targets = await self._expand_targets_from_subdomains(scan_id, targets)
            
            # Rate limiting between phases
            if self.enable_rate_limiting:
                await asyncio.sleep(2)
        
        return workflow_results

    async def _execute_phase(
        self,
        phase: WorkflowPhase,
        targets: List[str],
        scan_id: str,
        phase_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a single workflow phase.
        
        Args:
            phase: Workflow phase to execute
            targets: Target list for this phase
            scan_id: Scan session ID
            phase_config: Phase configuration
            
        Returns:
            Phase execution results
        """
        phase_start_time = datetime.utcnow()
        self.logger.info(f"Executing phase: {phase.value}")
        
        # Initialize phase progress tracking
        self._phase_progress[phase] = {
            "status": "running",
            "start_time": phase_start_time,
            "tools_completed": 0,
            "total_tools": len(phase_config["tools"]),
            "assets_discovered": 0
        }
        
        # Notify progress callbacks
        await self._notify_progress("phase_started", {
            "phase": phase.value,
            "targets": len(targets),
            "tools": phase_config["tools"]
        })
        
        phase_results = {
            "phase": phase.value,
            "status": "running",
            "tools": {},
            "assets_discovered": [],
            "errors": []
        }
        
        try:
            # Execute tools in this phase
            if phase_config.get("parallel", False):
                # Parallel execution
                tool_tasks = []
                for tool_name in phase_config["tools"]:
                    if tool_name in self._tools:
                        for target in targets:
                            task = self._execute_tool_on_target(
                                tool_name, target, scan_id
                            )
                            tool_tasks.append(task)
                
                # Wait for all tools to complete with concurrency limit
                semaphore = asyncio.Semaphore(self.max_concurrent_tools)
                results = await self._execute_with_semaphore(tool_tasks, semaphore)
                
                # Process results
                for tool_name, target, result in results:
                    if tool_name not in phase_results["tools"]:
                        phase_results["tools"][tool_name] = {}
                    phase_results["tools"][tool_name][target] = result
                    
                    if result.assets_discovered:
                        phase_results["assets_discovered"].extend(result.assets_discovered)
            
            else:
                # Sequential execution
                for tool_name in phase_config["tools"]:
                    if tool_name in self._tools:
                        tool_results = {}
                        for target in targets:
                            result = await self._execute_tool_on_target(
                                tool_name, target, scan_id
                            )
                            tool_results[target] = result
                            
                            if result.assets_discovered:
                                phase_results["assets_discovered"].extend(result.assets_discovered)
                        
                        phase_results["tools"][tool_name] = tool_results
            
            # Update phase completion
            phase_end_time = datetime.utcnow()
            phase_duration = (phase_end_time - phase_start_time).total_seconds()
            
            phase_results.update({
                "status": "completed",
                "start_time": phase_start_time.isoformat(),
                "end_time": phase_end_time.isoformat(),
                "duration_seconds": phase_duration,
                "assets_count": len(phase_results["assets_discovered"])
            })
            
            self._phase_progress[phase]["status"] = "completed"
            self._phase_progress[phase]["assets_discovered"] = len(phase_results["assets_discovered"])
            
            # Notify progress callbacks
            await self._notify_progress("phase_completed", {
                "phase": phase.value,
                "duration": phase_duration,
                "assets_discovered": len(phase_results["assets_discovered"])
            })
            
            self.logger.info(
                f"Phase {phase.value} completed: "
                f"{len(phase_results['assets_discovered'])} assets discovered"
            )
            
        except Exception as e:
            phase_results["status"] = "failed"
            phase_results["errors"].append(str(e))
            self._phase_progress[phase]["status"] = "failed"
            
            self.logger.error(f"Phase {phase.value} failed: {e}")
        
        return phase_results

    async def _execute_tool_on_target(
        self,
        tool_name: str,
        target: str,
        scan_id: str
    ) -> ReconResult:
        """
        Execute a specific tool against a target.
        
        Args:
            tool_name: Name of tool to execute
            target: Target domain/IP
            scan_id: Scan session ID
            
        Returns:
            Tool execution result
        """
        tool = self._tools.get(tool_name)
        if not tool:
            # Return failed result for missing tool
            return ReconResult(
                tool_name=tool_name,
                tool_version=None,
                target=target,
                status=ToolStatus.FAILED,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                error_message=f"Tool {tool_name} not available"
            )
        
        try:
            self.logger.info(f"Executing {tool_name} against {target}")
            
            # Get tool-specific options from workflow config
            tool_options = self._workflow_config.get("tools", {}).get(tool_name, {})
            
            # Execute tool with timeout
            result = await asyncio.wait_for(
                tool.execute(target, tool_options),
                timeout=self.default_timeout
            )
            
            # Store result using data collector
            await self.data_collector.store_scan_result(
                result, scan_id, target
            )
            
            # Record performance metrics
            if result.duration_seconds:
                await self.data_collector.record_performance_metric(
                    "tool_execution_time",
                    result.duration_seconds,
                    tool_name,
                    scan_id,
                    {"target": target, "status": result.status.value}
                )
            
            self._execution_metrics["tools_executed"] += 1
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Tool {tool_name} timed out for target {target}")
            return ReconResult(
                tool_name=tool_name,
                tool_version=await tool.get_tool_version() if tool else None,
                target=target,
                status=ToolStatus.TIMEOUT,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                error_message=f"Tool execution timed out after {self.default_timeout} seconds"
            )
            
        except Exception as e:
            self.logger.error(f"Tool {tool_name} failed for target {target}: {e}")
            return ReconResult(
                tool_name=tool_name,
                tool_version=await tool.get_tool_version() if tool else None,
                target=target,
                status=ToolStatus.FAILED,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                error_message=str(e)
            )

    async def _execute_with_semaphore(
        self,
        tasks: List[asyncio.Task],
        semaphore: asyncio.Semaphore
    ) -> List[Any]:
        """
        Execute tasks with semaphore-based concurrency control.
        
        Args:
            tasks: List of tasks to execute
            semaphore: Semaphore for concurrency control
            
        Returns:
            List of task results
        """
        async def _bounded_task(task):
            async with semaphore:
                return await task
        
        bounded_tasks = [_bounded_task(task) for task in tasks]
        return await asyncio.gather(*bounded_tasks, return_exceptions=True)

    async def _wait_for_dependencies(self, dependencies: List[WorkflowPhase]) -> None:
        """
        Wait for dependency phases to complete.
        
        Args:
            dependencies: List of dependency phases
        """
        for dep_phase in dependencies:
            while (dep_phase in self._phase_progress and 
                   self._phase_progress[dep_phase].get("status") == "running"):
                await asyncio.sleep(1)  # Poll every second
                
            # Check if dependency failed
            if (dep_phase in self._phase_progress and 
                self._phase_progress[dep_phase].get("status") == "failed"):
                raise Exception(f"Dependency phase {dep_phase.value} failed")

    async def _expand_targets_from_subdomains(
        self,
        scan_id: str,
        original_targets: List[str]
    ) -> List[str]:
        """
        Expand target list with discovered subdomains.
        
        Args:
            scan_id: Scan session ID
            original_targets: Original target list
            
        Returns:
            Expanded target list
        """
        try:
            # Get discovered assets from subdomain discovery
            assets = await self.data_collector.get_assets_by_scan(scan_id)
            
            # Extract unique subdomains
            expanded_targets = set(original_targets)
            
            for asset in assets:
                subdomain = asset.get("subdomain")
                if subdomain and subdomain not in expanded_targets:
                    expanded_targets.add(subdomain)
                    
                ip_address = asset.get("ip_address")
                if ip_address and ip_address not in expanded_targets:
                    expanded_targets.add(ip_address)
            
            expanded_list = list(expanded_targets)
            
            if len(expanded_list) > len(original_targets):
                self.logger.info(
                    f"Expanded targets from {len(original_targets)} to {len(expanded_list)}"
                )
            
            return expanded_list
            
        except Exception as e:
            self.logger.error(f"Failed to expand targets: {e}")
            return original_targets

    async def _initialize_scan_session(self, scan_id: str, targets: List[str]) -> None:
        """
        Initialize scan session in database.
        
        Args:
            scan_id: Scan session ID
            targets: Target list
        """
        try:
            if self.database_manager:
                scan_data = {
                    "scan_id": scan_id,
                    "scan_type": "comprehensive_recon",
                    "domains_scanned": targets,
                    "scan_config": self._workflow_config,
                    "status": "running",
                    "total_domains": len(targets)
                }
                
                await self.database_manager.create_scan_session(scan_data)
                self.logger.info(f"Initialized scan session {scan_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize scan session: {e}")

    async def _finalize_scan(
        self,
        scan_id: str,
        workflow_results: Dict[str, Any],
        scan_start_time: datetime
    ) -> Dict[str, Any]:
        """
        Finalize scan and generate comprehensive results.
        
        Args:
            scan_id: Scan session ID
            workflow_results: Workflow execution results
            scan_start_time: Scan start timestamp
            
        Returns:
            Final scan results
        """
        scan_end_time = datetime.utcnow()
        total_duration = (scan_end_time - scan_start_time).total_seconds()
        
        # Collect all discovered assets
        all_assets = []
        for phase_results in workflow_results.get("phases", {}).values():
            all_assets.extend(phase_results.get("assets_discovered", []))
        
        # Generate summary statistics
        summary_stats = {
            "total_assets": len(all_assets),
            "unique_domains": len(set(asset.get("domain", "") for asset in all_assets)),
            "unique_subdomains": len(set(asset.get("subdomain", "") for asset in all_assets if asset.get("subdomain"))),
            "unique_ips": len(set(asset.get("ip_address", "") for asset in all_assets if asset.get("ip_address"))),
            "services_detected": len(set(asset.get("service", "") for asset in all_assets if asset.get("service"))),
            "ports_discovered": len(set(asset.get("port") for asset in all_assets if asset.get("port")))
        }
        
        # Update execution metrics
        self._execution_metrics["scans_completed"] += 1
        self._execution_metrics["total_execution_time"] += total_duration
        
        # Update scan session status
        if self.database_manager:
            await self.database_manager.update_scan_session(scan_id, {
                "status": "completed",
                "end_time": scan_end_time,
                "duration_seconds": total_duration,
                "assets_discovered": len(all_assets)
            })
        
        final_results = {
            "scan_id": scan_id,
            "status": "completed",
            "start_time": scan_start_time.isoformat(),
            "end_time": scan_end_time.isoformat(),
            "duration_seconds": total_duration,
            "targets_scanned": list(self.current_targets),
            "workflow_results": workflow_results,
            "summary_statistics": summary_stats,
            "performance_metrics": self._execution_metrics.copy(),
            "phase_progress": {phase.value: progress for phase, progress in self._phase_progress.items()}
        }
        
        self.logger.info(
            f"Scan {scan_id} finalized: {summary_stats['total_assets']} assets discovered "
            f"in {total_duration:.1f} seconds"
        )
        
        return final_results

    async def _cleanup_scan(self, scan_id: str) -> None:
        """
        Cleanup scan-related resources.
        
        Args:
            scan_id: Scan session ID to cleanup
        """
        try:
            # Cancel any remaining active tasks
            for task_id, task in self._active_tasks.items():
                if not task.done():
                    task.cancel()
            
            # Clear scan state
            self._active_tasks.clear()
            self._completed_tasks.clear()
            self._failed_tasks.clear()
            self._phase_progress.clear()
            
            self.current_scan_id = None
            self.current_targets.clear()
            self.status = OrchestratorStatus.IDLE
            
        except Exception as e:
            self.logger.error(f"Cleanup failed for scan {scan_id}: {e}")

    def _get_partial_results(self) -> Dict[str, Any]:
        """
        Get partial results from incomplete scan.
        
        Returns:
            Partial results dictionary
        """
        return {
            "completed_tasks": {k: v.to_dict() for k, v in self._completed_tasks.items()},
            "failed_tasks": {k: str(v) for k, v in self._failed_tasks.items()},
            "phase_progress": {phase.value: progress for phase, progress in self._phase_progress.items()}
        }

    async def _notify_progress(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """
        Notify registered progress callbacks.
        
        Args:
            event_type: Type of progress event
            event_data: Event data
        """
        try:
            progress_info = {
                "scan_id": self.current_scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "data": event_data
            }
            
            for callback in self._progress_callbacks:
                try:
                    callback(progress_info)
                except Exception as e:
                    self.logger.error(f"Progress callback failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"Progress notification failed: {e}")

    def add_progress_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Add progress callback function.
        
        Args:
            callback: Callback function to add
        """
        self._progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Remove progress callback function.
        
        Args:
            callback: Callback function to remove
        """
        if callback in self._progress_callbacks:
            self._progress_callbacks.remove(callback)

    async def cancel_scan(self) -> bool:
        """
        Cancel currently running scan.
        
        Returns:
            True if cancellation successful
        """
        try:
            if self.status == OrchestratorStatus.RUNNING:
                self.status = OrchestratorStatus.CANCELLED
                
                # Cancel all active tasks
                for task in self._active_tasks.values():
                    if not task.done():
                        task.cancel()
                
                self.logger.info(f"Scan {self.current_scan_id} cancelled")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to cancel scan: {e}")
            return False

    async def pause_scan(self) -> bool:
        """
        Pause currently running scan.
        
        Returns:
            True if pause successful
        """
        # Note: This is a simplified pause implementation
        # A full implementation would need more sophisticated task management
        if self.status == OrchestratorStatus.RUNNING:
            self.status = OrchestratorStatus.PAUSED
            self.logger.info(f"Scan {self.current_scan_id} paused")
            return True
        return False

    async def resume_scan(self) -> bool:
        """
        Resume paused scan.
        
        Returns:
            True if resume successful
        """
        if self.status == OrchestratorStatus.PAUSED:
            self.status = OrchestratorStatus.RUNNING
            self.logger.info(f"Scan {self.current_scan_id} resumed")
            return True
        return False

    def get_scan_status(self) -> Dict[str, Any]:
        """
        Get current scan status and progress.
        
        Returns:
            Status information
        """
        return {
            "status": self.status.value,
            "scan_id": self.current_scan_id,
            "targets": list(self.current_targets),
            "phase_progress": {phase.value: progress for phase, progress in self._phase_progress.items()},
            "execution_metrics": self._execution_metrics.copy(),
            "available_tools": list(self._tools.keys()),
            "active_tasks": len(self._active_tasks),
            "completed_tasks": len(self._completed_tasks),
            "failed_tasks": len(self._failed_tasks)
        }

    def get_execution_metrics(self) -> Dict[str, Any]:
        """
        Get execution performance metrics.
        
        Returns:
            Performance metrics
        """
        metrics = self._execution_metrics.copy()
        
        if metrics["tools_executed"] > 0:
            metrics["average_tool_time"] = metrics["total_execution_time"] / metrics["tools_executed"]
            metrics["error_rate"] = len(self._failed_tasks) / metrics["tools_executed"] * 100
        
        return metrics