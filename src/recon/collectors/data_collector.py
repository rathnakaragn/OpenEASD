"""
OpenEASD Recon Layer - Data Collector
6-Layer Architecture - Recon Layer

Data collector for storing and managing reconnaissance tool outputs.
Integrates with the Database Layer for persistent storage.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import uuid

from ...interfaces.tool import ReconResult
from ...db.database.duckdb_manager import DuckDBManager
from ...db.models.asset_inventory import AssetInventoryCreate
from ...db.models.scan_progress import ScanProgressCreate, ScanProgressUpdate


class DataCollector:
    """
    Data collector for reconnaissance tool outputs.
    
    Features:
    - Tool output storage and retrieval
    - Asset inventory management
    - Scan progress tracking
    - Data deduplication and validation
    - Integration with Database Layer
    - Performance metrics collection
    """
    
    def __init__(self, database_manager: Optional[DuckDBManager] = None):
        """
        Initialize the data collector.
        
        Args:
            database_manager: Database manager instance
        """
        self.database_manager = database_manager
        self.logger = logging.getLogger(f"{__name__}.DataCollector")
        
        # In-memory storage for when database is unavailable
        self._memory_storage = {
            "scan_results": {},
            "assets": {},
            "progress_entries": {},
            "metrics": []
        }
        
        # Statistics tracking
        self._stats = {
            "results_stored": 0,
            "assets_created": 0,
            "assets_updated": 0,
            "progress_entries": 0,
            "storage_errors": 0
        }

    async def store_scan_result(
        self,
        result: ReconResult,
        scan_id: str,
        domain: str,
        store_raw_output: bool = True
    ) -> str:
        """
        Store a complete scan result from a reconnaissance tool.
        
        Args:
            result: ReconResult from tool execution
            scan_id: Parent scan session ID
            domain: Domain being scanned
            store_raw_output: Whether to store raw tool output
            
        Returns:
            Unique identifier for stored result
        """
        result_id = str(uuid.uuid4())
        
        try:
            # Create progress entry for this tool execution
            progress_id = await self._create_progress_entry(result, scan_id, domain)
            
            # Store discovered assets
            asset_ids = []
            if result.assets_discovered:
                asset_ids = await self._store_discovered_assets(
                    result.assets_discovered,
                    scan_id,
                    result.tool_name
                )
            
            # Store raw output if requested and database available
            raw_output_id = None
            if store_raw_output and self.database_manager and result.raw_output:
                raw_output_id = await self._store_raw_output(
                    result,
                    scan_id,
                    result_id
                )
            
            # Create summary entry
            result_summary = {
                "result_id": result_id,
                "scan_id": scan_id,
                "domain": domain,
                "tool_name": result.tool_name,
                "tool_version": result.tool_version,
                "target": result.target,
                "status": result.status.value,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": result.duration_seconds,
                "assets_count": len(result.assets_discovered),
                "asset_ids": asset_ids,
                "progress_id": progress_id,
                "raw_output_id": raw_output_id,
                "parsed_data": result.parsed_data,
                "error_message": result.error_message,
                "return_code": result.return_code,
                "command_line": result.command_line,
                "resource_usage": result.resource_usage,
                "stored_at": datetime.utcnow().isoformat()
            }
            
            # Store in database or memory
            if self.database_manager:
                await self._store_result_in_database(result_summary)
            else:
                self._memory_storage["scan_results"][result_id] = result_summary
            
            self._stats["results_stored"] += 1
            self.logger.info(f"Stored scan result for {result.tool_name} on {domain}")
            
            return result_id
            
        except Exception as e:
            self.logger.error(f"Failed to store scan result: {e}")
            self._stats["storage_errors"] += 1
            
            # Store minimal info in memory as fallback
            self._memory_storage["scan_results"][result_id] = {
                "result_id": result_id,
                "scan_id": scan_id,
                "domain": domain,
                "tool_name": result.tool_name,
                "status": result.status.value,
                "error": str(e),
                "stored_at": datetime.utcnow().isoformat()
            }
            
            return result_id

    async def _create_progress_entry(
        self,
        result: ReconResult,
        scan_id: str,
        domain: str
    ) -> str:
        """
        Create scan progress entry for the tool execution.
        
        Args:
            result: ReconResult from tool execution
            scan_id: Parent scan session ID
            domain: Domain being scanned
            
        Returns:
            Progress entry ID
        """
        try:
            if self.database_manager:
                # Create progress entry using database manager
                progress_data = {
                    "scan_id": scan_id,
                    "domain": domain,
                    "phase": self._map_tool_to_phase(result.tool_name),
                    "tool": result.tool_name,
                    "status": self._map_result_status_to_tool_status(result.status),
                    "start_time": result.start_time,
                    "end_time": result.end_time,
                    "progress_percentage": 100 if result.is_success() else 0,
                    "results_count": len(result.assets_discovered),
                    "error_message": result.error_message,
                    "tool_version": result.tool_version,
                    "command_line": result.command_line,
                    "raw_output_size": len(result.raw_output.encode('utf-8')) if result.raw_output else 0
                }
                
                return await self.database_manager.create_scan_progress(progress_data)
            else:
                # Store in memory
                progress_id = str(uuid.uuid4())
                self._memory_storage["progress_entries"][progress_id] = {
                    "id": progress_id,
                    "scan_id": scan_id,
                    "domain": domain,
                    "tool": result.tool_name,
                    "status": result.status.value,
                    "start_time": result.start_time.isoformat(),
                    "end_time": result.end_time.isoformat() if result.end_time else None,
                    "results_count": len(result.assets_discovered)
                }
                return progress_id
                
        except Exception as e:
            self.logger.error(f"Failed to create progress entry: {e}")
            return str(uuid.uuid4())  # Return dummy ID

    async def _store_discovered_assets(
        self,
        assets: List[Dict[str, Any]],
        scan_id: str,
        tool_name: str
    ) -> List[str]:
        """
        Store discovered assets in the asset inventory.
        
        Args:
            assets: List of discovered assets
            scan_id: Parent scan session ID
            tool_name: Name of discovery tool
            
        Returns:
            List of asset IDs
        """
        asset_ids = []
        
        for asset_data in assets:
            try:
                # Add scan metadata
                asset_data["scan_source"] = tool_name
                asset_data["scan_id"] = scan_id
                
                if self.database_manager:
                    # Store using database manager
                    asset_id = await self.database_manager.upsert_asset(asset_data)
                    asset_ids.append(asset_id)
                    self._stats["assets_created"] += 1
                else:
                    # Store in memory
                    asset_id = str(uuid.uuid4())
                    self._memory_storage["assets"][asset_id] = {
                        **asset_data,
                        "id": asset_id,
                        "stored_at": datetime.utcnow().isoformat()
                    }
                    asset_ids.append(asset_id)
                    
            except Exception as e:
                self.logger.error(f"Failed to store asset: {e}")
                self._stats["storage_errors"] += 1
        
        return asset_ids

    async def _store_raw_output(
        self,
        result: ReconResult,
        scan_id: str,
        result_id: str
    ) -> Optional[str]:
        """
        Store raw tool output for forensic analysis.
        
        Args:
            result: ReconResult containing raw output
            scan_id: Parent scan session ID
            result_id: Result identifier
            
        Returns:
            Raw output storage ID or None
        """
        try:
            if not result.raw_output:
                return None
                
            raw_output_id = str(uuid.uuid4())
            
            if self.database_manager:
                # Store as a metric entry for now (could be extended)
                await self.database_manager.record_metric(
                    metric_type="raw_output",
                    metric_value=len(result.raw_output),
                    metric_unit="bytes",
                    dimensions={
                        "tool": result.tool_name,
                        "result_id": result_id,
                        "output_preview": result.raw_output[:500] + "..." if len(result.raw_output) > 500 else result.raw_output
                    },
                    scan_id=scan_id,
                    tool=result.tool_name
                )
                
            return raw_output_id
            
        except Exception as e:
            self.logger.error(f"Failed to store raw output: {e}")
            return None

    async def _store_result_in_database(self, result_summary: Dict[str, Any]) -> None:
        """
        Store result summary in database.
        
        Args:
            result_summary: Summary data to store
        """
        # For now, store as a system metric
        # In a full implementation, you might have a dedicated results table
        await self.database_manager.record_metric(
            metric_type="scan_result",
            metric_value=result_summary.get("assets_count", 0),
            metric_unit="assets",
            dimensions=result_summary,
            scan_id=result_summary.get("scan_id"),
            tool=result_summary.get("tool_name")
        )

    def _map_tool_to_phase(self, tool_name: str) -> str:
        """
        Map tool name to scan phase.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Corresponding scan phase
        """
        phase_mapping = {
            "subfinder": "subdomain_discovery",
            "nmap": "service_detection", 
            "naabu": "port_scanning",
            "whois": "whois_analysis"
        }
        
        return phase_mapping.get(tool_name.lower(), "unknown")

    def _map_result_status_to_tool_status(self, result_status) -> str:
        """
        Map ReconResult status to tool status for progress tracking.
        
        Args:
            result_status: ReconResult status
            
        Returns:
            Tool status string
        """
        from ...interfaces.tool import ToolStatus
        
        mapping = {
            ToolStatus.PENDING: "pending",
            ToolStatus.RUNNING: "running",
            ToolStatus.COMPLETED: "completed",
            ToolStatus.FAILED: "failed",
            ToolStatus.TIMEOUT: "timeout",
            ToolStatus.CANCELLED: "cancelled"
        }
        
        return mapping.get(result_status, "unknown")

    async def get_scan_results(
        self,
        scan_id: Optional[str] = None,
        domain: Optional[str] = None,
        tool_name: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve stored scan results with optional filtering.
        
        Args:
            scan_id: Filter by scan session ID
            domain: Filter by domain
            tool_name: Filter by tool name
            limit: Maximum number of results
            
        Returns:
            List of scan results
        """
        try:
            results = []
            
            if self.database_manager:
                # Query database (implementation would depend on actual table structure)
                # For now, return empty list as this would need specific database queries
                pass
            
            # Search memory storage
            for result in self._memory_storage["scan_results"].values():
                # Apply filters
                if scan_id and result.get("scan_id") != scan_id:
                    continue
                if domain and result.get("domain") != domain:
                    continue
                if tool_name and result.get("tool_name") != tool_name:
                    continue
                
                results.append(result)
            
            # Sort by stored time (most recent first)
            results.sort(key=lambda x: x.get("stored_at", ""), reverse=True)
            
            # Apply limit
            if limit:
                results = results[:limit]
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve scan results: {e}")
            return []

    async def get_assets_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all assets discovered in a specific scan.
        
        Args:
            scan_id: Scan session ID
            
        Returns:
            List of assets
        """
        try:
            if self.database_manager:
                # Use database manager to get assets
                return await self.database_manager.get_assets()
            else:
                # Search memory storage
                assets = []
                for asset in self._memory_storage["assets"].values():
                    if asset.get("scan_id") == scan_id:
                        assets.append(asset)
                return assets
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve assets for scan {scan_id}: {e}")
            return []

    async def update_scan_progress(
        self,
        progress_id: str,
        updates: Dict[str, Any]
    ) -> bool:
        """
        Update scan progress entry.
        
        Args:
            progress_id: Progress entry ID
            updates: Fields to update
            
        Returns:
            True if update successful
        """
        try:
            if self.database_manager:
                return await self.database_manager.update_scan_progress(progress_id, updates)
            else:
                # Update memory storage
                if progress_id in self._memory_storage["progress_entries"]:
                    self._memory_storage["progress_entries"][progress_id].update(updates)
                    return True
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to update scan progress: {e}")
            return False

    async def record_performance_metric(
        self,
        metric_type: str,
        metric_value: float,
        tool_name: str,
        scan_id: str,
        dimensions: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record performance metrics for tool execution.
        
        Args:
            metric_type: Type of metric (e.g., "execution_time", "memory_usage")
            metric_value: Metric value
            tool_name: Tool that generated the metric
            scan_id: Associated scan session
            dimensions: Additional metric dimensions
        """
        try:
            metric_entry = {
                "metric_type": metric_type,
                "metric_value": metric_value,
                "tool_name": tool_name,
                "scan_id": scan_id,
                "dimensions": dimensions or {},
                "recorded_at": datetime.utcnow().isoformat()
            }
            
            if self.database_manager:
                await self.database_manager.record_metric(
                    metric_type=metric_type,
                    metric_value=metric_value,
                    dimensions=dimensions,
                    scan_id=scan_id,
                    tool=tool_name
                )
            else:
                self._memory_storage["metrics"].append(metric_entry)
            
        except Exception as e:
            self.logger.error(f"Failed to record performance metric: {e}")

    def get_collection_statistics(self) -> Dict[str, Any]:
        """
        Get data collection statistics.
        
        Returns:
            Statistics dictionary
        """
        memory_stats = {
            "scan_results_count": len(self._memory_storage["scan_results"]),
            "assets_count": len(self._memory_storage["assets"]),
            "progress_entries_count": len(self._memory_storage["progress_entries"]),
            "metrics_count": len(self._memory_storage["metrics"])
        }
        
        return {
            **self._stats,
            "memory_storage": memory_stats,
            "database_available": self.database_manager is not None,
            "collection_active_since": datetime.utcnow().isoformat()
        }

    async def cleanup_old_data(self, days_old: int = 30) -> Dict[str, int]:
        """
        Clean up old scan data to manage storage.
        
        Args:
            days_old: Age threshold in days
            
        Returns:
            Cleanup statistics
        """
        cleanup_stats = {
            "scan_results_cleaned": 0,
            "assets_cleaned": 0,
            "progress_entries_cleaned": 0,
            "metrics_cleaned": 0
        }
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            cutoff_iso = cutoff_date.isoformat()
            
            # Clean memory storage
            for storage_type in ["scan_results", "assets", "progress_entries"]:
                storage = self._memory_storage[storage_type]
                to_remove = []
                
                for key, item in storage.items():
                    stored_at = item.get("stored_at", "")
                    if stored_at and stored_at < cutoff_iso:
                        to_remove.append(key)
                
                for key in to_remove:
                    del storage[key]
                    cleanup_stats[f"{storage_type}_cleaned"] += 1
            
            # Clean metrics
            metrics = self._memory_storage["metrics"]
            self._memory_storage["metrics"] = [
                m for m in metrics 
                if m.get("recorded_at", "") >= cutoff_iso
            ]
            cleanup_stats["metrics_cleaned"] = len(metrics) - len(self._memory_storage["metrics"])
            
            self.logger.info(f"Cleaned up data older than {days_old} days: {cleanup_stats}")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
        
        return cleanup_stats

    async def export_scan_data(
        self,
        scan_id: str,
        export_format: str = "json"
    ) -> Optional[Dict[str, Any]]:
        """
        Export comprehensive scan data for a specific scan session.
        
        Args:
            scan_id: Scan session ID to export
            export_format: Export format ("json", "csv", etc.)
            
        Returns:
            Exported data or None if failed
        """
        try:
            export_data = {
                "scan_id": scan_id,
                "export_timestamp": datetime.utcnow().isoformat(),
                "export_format": export_format,
                "scan_results": await self.get_scan_results(scan_id=scan_id),
                "assets": await self.get_assets_by_scan(scan_id),
                "statistics": self.get_collection_statistics()
            }
            
            self.logger.info(f"Exported scan data for scan {scan_id}")
            return export_data
            
        except Exception as e:
            self.logger.error(f"Failed to export scan data: {e}")
            return None

    async def validate_data_integrity(self) -> Dict[str, Any]:
        """
        Validate data integrity across storage systems.
        
        Returns:
            Integrity validation report
        """
        validation_report = {
            "validation_timestamp": datetime.utcnow().isoformat(),
            "database_available": self.database_manager is not None,
            "memory_storage_healthy": True,
            "consistency_checks": {},
            "recommendations": []
        }
        
        try:
            # Check memory storage consistency
            for storage_type, storage in self._memory_storage.items():
                if not isinstance(storage, (dict, list)):
                    validation_report["memory_storage_healthy"] = False
                    validation_report["recommendations"].append(f"Reset {storage_type} storage")
            
            # Check data relationships
            scan_results = self._memory_storage["scan_results"]
            assets = self._memory_storage["assets"]
            
            orphaned_assets = 0
            for asset in assets.values():
                scan_id = asset.get("scan_id")
                if scan_id and not any(r.get("scan_id") == scan_id for r in scan_results.values()):
                    orphaned_assets += 1
            
            validation_report["consistency_checks"]["orphaned_assets"] = orphaned_assets
            
            if orphaned_assets > 0:
                validation_report["recommendations"].append(
                    f"Clean up {orphaned_assets} orphaned assets"
                )
            
            self.logger.info("Data integrity validation completed")
            
        except Exception as e:
            self.logger.error(f"Data integrity validation failed: {e}")
            validation_report["validation_error"] = str(e)
        
        return validation_report