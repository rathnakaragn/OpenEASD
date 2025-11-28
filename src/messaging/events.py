"""
Event schemas for the messaging layer.

All events follow a common structure with event_type, timestamp, and optional scan_id.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any


class EventType(Enum):
    """Event type enumeration for all messaging events."""

    # Scan lifecycle events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # Tool execution events
    TOOL_STARTED = "scan.tool.started"
    TOOL_COMPLETED = "scan.tool.completed"
    TOOL_FAILED = "scan.tool.failed"

    # Finding/alert events
    FINDING_DISCOVERED = "finding.discovered"
    ALERT_CREATED = "alert.created"

    # Analysis events
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"


@dataclass
class BaseEvent:
    """
    Base event with common fields.

    All events inherit from this base class to ensure consistency.
    """
    event_type: str
    timestamp: str  # ISO format timestamp

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return asdict(self)


@dataclass
class ScanStartedEvent(BaseEvent):
    """
    Event emitted when a scan starts.

    Published by: ScanService.execute_scan()
    Subscribed by: CLI (progress display), API (WebSocket)
    """
    scan_id: str
    domain: str
    scan_type: str  # e.g., "passive_subdomain_enum", "full_scan"
    tool_name: str  # Initial tool (usually "subfinder")


@dataclass
class ScanCompletedEvent(BaseEvent):
    """
    Event emitted when a scan completes successfully.

    Published by: ScanService.execute_scan()
    Subscribed by: CLI (final status), API (WebSocket), Monitoring
    """
    scan_id: str
    domain: str
    findings_count: int
    duration_seconds: float
    tools_executed: list  # List of tool names executed


@dataclass
class ScanFailedEvent(BaseEvent):
    """
    Event emitted when a scan fails.

    Published by: ScanService.execute_scan()
    Subscribed by: CLI (error display), API (WebSocket), Monitoring
    """
    scan_id: str
    domain: str
    error: str
    tool_name: Optional[str] = None  # Tool that failed (if applicable)


@dataclass
class ToolStartedEvent(BaseEvent):
    """
    Event emitted when a tool starts execution.

    Published by: ScanService (before running each tool)
    Subscribed by: CLI (progress display), API (WebSocket)
    """
    scan_id: str
    tool_name: str  # subfinder, dnsx, naabu, httpx
    domain: str
    target_count: Optional[int] = None  # Number of targets (for dnsx, naabu, httpx)


@dataclass
class ToolCompletedEvent(BaseEvent):
    """
    Event emitted when a tool completes execution.

    Published by: ScanService (after running each tool)
    Subscribed by: CLI (progress display), API (WebSocket), Monitoring
    """
    scan_id: str
    tool_name: str  # subfinder, dnsx, naabu, httpx
    domain: str
    results_count: int
    duration_seconds: float


@dataclass
class ToolFailedEvent(BaseEvent):
    """
    Event emitted when a tool fails.

    Published by: ScanService (if tool execution fails)
    Subscribed by: CLI (error display), API (WebSocket), Monitoring
    """
    scan_id: str
    tool_name: str
    domain: str
    error: str


@dataclass
class FindingDiscoveredEvent(BaseEvent):
    """
    Event emitted when a security finding is discovered.

    Published by: AnalysisService (during analysis)
    Subscribed by: CLI (real-time alerts), API (WebSocket), Alerting system
    """
    scan_id: str
    finding_id: str
    finding_type: str  # e.g., "database_port_exposed", "subdomain_discovered"
    severity: str  # critical, high, medium, low, info
    affected_asset: str  # domain or subdomain
    risk_score: int  # 0-100
    port: Optional[int] = None
    protocol: Optional[str] = None
    title: Optional[str] = None


@dataclass
class AlertCreatedEvent(BaseEvent):
    """
    Event emitted when an alert is created.

    Published by: AlertService (when alert threshold met)
    Subscribed by: Notification system, Dashboard
    """
    scan_id: str
    alert_id: str
    alert_type: str
    severity: str
    domain: str
    description: str


@dataclass
class AnalysisStartedEvent(BaseEvent):
    """
    Event emitted when analysis starts on scan results.

    Published by: AnalysisService.analyze_scan_results()
    Subscribed by: CLI (progress display), API (WebSocket)
    """
    scan_id: str
    detector_count: int  # Number of detectors to run


@dataclass
class AnalysisCompletedEvent(BaseEvent):
    """
    Event emitted when analysis completes.

    Published by: AnalysisService.analyze_scan_results()
    Subscribed by: CLI (progress display), API (WebSocket), Monitoring
    """
    scan_id: str
    findings_count: int
    duration_seconds: float
    detectors_run: list  # List of detector names


@dataclass
class AnalysisFailedEvent(BaseEvent):
    """
    Event emitted when analysis fails.

    Published by: AnalysisService (on error)
    Subscribed by: CLI (error display), Monitoring
    """
    scan_id: str
    error: str
