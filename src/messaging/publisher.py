"""
Event publisher interface for the messaging layer.

Provides type-safe methods for publishing events to the ZeroMQ event bus.
"""

import json
import logging
from typing import Optional, List
from datetime import datetime

from src.messaging.bus import EventBus
from src.messaging.events import (
    EventType,
    ScanStartedEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
    ToolStartedEvent,
    ToolCompletedEvent,
    ToolFailedEvent,
    FindingDiscoveredEvent,
    AlertCreatedEvent,
    AnalysisStartedEvent,
    AnalysisCompletedEvent,
    AnalysisFailedEvent
)
from src.utils.timezone import get_ist_now

logger = logging.getLogger(__name__)


class EventPublisher:
    """
    Publishes events to ZeroMQ event bus with type safety.

    This class provides convenience methods for publishing all event types
    defined in the messaging layer. Used primarily by the Service Layer.

    Usage:
        bus = EventBus()
        bus.start()
        publisher = EventPublisher(bus)

        publisher.publish_scan_started(
            scan_id="scan-123",
            domain="example.com",
            scan_type="passive",
            tool_name="subfinder"
        )
    """

    def __init__(self, bus: EventBus):
        """
        Initialize event publisher.

        Args:
            bus: EventBus instance to publish to
        """
        self.bus = bus

    def _publish_event(self, topic: str, event_data: dict) -> None:
        """
        Internal method to publish an event.

        Args:
            topic: Topic name for filtering
            event_data: Event data dictionary

        Raises:
            RuntimeError: If bus is not running
            json.JSONEncodeError: If event data cannot be serialized
        """
        try:
            message = json.dumps(event_data).encode('utf-8')
            self.bus.publish(topic, message)
        except Exception as e:
            logger.error(f"Failed to publish event to '{topic}': {e}", exc_info=True)
            raise

    def publish_scan_started(
        self,
        scan_id: str,
        domain: str,
        scan_type: str,
        tool_name: str
    ) -> None:
        """
        Publish scan started event.

        Args:
            scan_id: Unique scan identifier
            domain: Target domain
            scan_type: Type of scan (e.g., "passive_subdomain_enum")
            tool_name: Initial tool name
        """
        event = ScanStartedEvent(
            event_type=EventType.SCAN_STARTED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            domain=domain,
            scan_type=scan_type,
            tool_name=tool_name
        )
        self._publish_event(f"scan.{scan_id}.started", event.to_dict())
        logger.info(f"Published scan started: {scan_id} for {domain}")

    def publish_scan_completed(
        self,
        scan_id: str,
        domain: str,
        findings_count: int,
        duration_seconds: float,
        tools_executed: List[str]
    ) -> None:
        """
        Publish scan completed event.

        Args:
            scan_id: Unique scan identifier
            domain: Target domain
            findings_count: Number of findings discovered
            duration_seconds: Total scan duration
            tools_executed: List of tools that were executed
        """
        event = ScanCompletedEvent(
            event_type=EventType.SCAN_COMPLETED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            domain=domain,
            findings_count=findings_count,
            duration_seconds=duration_seconds,
            tools_executed=tools_executed
        )
        self._publish_event(f"scan.{scan_id}.completed", event.to_dict())
        logger.info(f"Published scan completed: {scan_id} ({findings_count} findings)")

    def publish_scan_failed(
        self,
        scan_id: str,
        domain: str,
        error: str,
        tool_name: Optional[str] = None
    ) -> None:
        """
        Publish scan failed event.

        Args:
            scan_id: Unique scan identifier
            domain: Target domain
            error: Error message
            tool_name: Tool that caused the failure (if applicable)
        """
        event = ScanFailedEvent(
            event_type=EventType.SCAN_FAILED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            domain=domain,
            error=error,
            tool_name=tool_name
        )
        self._publish_event(f"scan.{scan_id}.failed", event.to_dict())
        logger.error(f"Published scan failed: {scan_id} - {error}")

    def publish_tool_started(
        self,
        scan_id: str,
        tool_name: str,
        domain: str,
        target_count: Optional[int] = None
    ) -> None:
        """
        Publish tool started event.

        Args:
            scan_id: Unique scan identifier
            tool_name: Tool being executed (subfinder, dnsx, naabu, httpx)
            domain: Target domain
            target_count: Number of targets (for dnsx, naabu, httpx)
        """
        event = ToolStartedEvent(
            event_type=EventType.TOOL_STARTED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            tool_name=tool_name,
            domain=domain,
            target_count=target_count
        )
        self._publish_event(f"tool.{tool_name}.started", event.to_dict())
        logger.debug(f"Published tool started: {tool_name} for {scan_id}")

    def publish_tool_completed(
        self,
        scan_id: str,
        tool_name: str,
        domain: str,
        results_count: int,
        duration_seconds: float
    ) -> None:
        """
        Publish tool completed event.

        Args:
            scan_id: Unique scan identifier
            tool_name: Tool that completed
            domain: Target domain
            results_count: Number of results found
            duration_seconds: Tool execution duration
        """
        event = ToolCompletedEvent(
            event_type=EventType.TOOL_COMPLETED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            tool_name=tool_name,
            domain=domain,
            results_count=results_count,
            duration_seconds=duration_seconds
        )
        self._publish_event(f"tool.{tool_name}.completed", event.to_dict())
        logger.info(f"Published tool completed: {tool_name} - {results_count} results ({duration_seconds:.1f}s)")

    def publish_tool_failed(
        self,
        scan_id: str,
        tool_name: str,
        domain: str,
        error: str
    ) -> None:
        """
        Publish tool failed event.

        Args:
            scan_id: Unique scan identifier
            tool_name: Tool that failed
            domain: Target domain
            error: Error message
        """
        event = ToolFailedEvent(
            event_type=EventType.TOOL_FAILED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            tool_name=tool_name,
            domain=domain,
            error=error
        )
        self._publish_event(f"tool.{tool_name}.failed", event.to_dict())
        logger.error(f"Published tool failed: {tool_name} - {error}")

    def publish_finding_discovered(
        self,
        scan_id: str,
        finding_id: str,
        finding_type: str,
        severity: str,
        affected_asset: str,
        risk_score: int,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        title: Optional[str] = None
    ) -> None:
        """
        Publish finding discovered event.

        Args:
            scan_id: Unique scan identifier
            finding_id: Unique finding identifier
            finding_type: Type of finding
            severity: Severity level (critical, high, medium, low, info)
            affected_asset: Domain or subdomain affected
            risk_score: Risk score (0-100)
            port: Port number (if applicable)
            protocol: Protocol (if applicable)
            title: Finding title
        """
        event = FindingDiscoveredEvent(
            event_type=EventType.FINDING_DISCOVERED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            affected_asset=affected_asset,
            risk_score=risk_score,
            port=port,
            protocol=protocol,
            title=title
        )
        self._publish_event(f"finding.{severity}.discovered", event.to_dict())
        logger.info(f"Published finding discovered: {finding_type} ({severity}) on {affected_asset}")

    def publish_alert_created(
        self,
        scan_id: str,
        alert_id: str,
        alert_type: str,
        severity: str,
        domain: str,
        description: str
    ) -> None:
        """
        Publish alert created event.

        Args:
            scan_id: Unique scan identifier
            alert_id: Unique alert identifier
            alert_type: Type of alert
            severity: Severity level
            domain: Target domain
            description: Alert description
        """
        event = AlertCreatedEvent(
            event_type=EventType.ALERT_CREATED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            domain=domain,
            description=description
        )
        self._publish_event(f"alert.{severity}.created", event.to_dict())
        logger.info(f"Published alert created: {alert_type} ({severity})")

    def publish_analysis_started(
        self,
        scan_id: str,
        detector_count: int
    ) -> None:
        """
        Publish analysis started event.

        Args:
            scan_id: Unique scan identifier
            detector_count: Number of detectors to run
        """
        event = AnalysisStartedEvent(
            event_type=EventType.ANALYSIS_STARTED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            detector_count=detector_count
        )
        self._publish_event(f"analysis.{scan_id}.started", event.to_dict())
        logger.info(f"Published analysis started: {scan_id} ({detector_count} detectors)")

    def publish_analysis_completed(
        self,
        scan_id: str,
        findings_count: int,
        duration_seconds: float,
        detectors_run: List[str]
    ) -> None:
        """
        Publish analysis completed event.

        Args:
            scan_id: Unique scan identifier
            findings_count: Number of findings discovered
            duration_seconds: Analysis duration
            detectors_run: List of detectors that were executed
        """
        event = AnalysisCompletedEvent(
            event_type=EventType.ANALYSIS_COMPLETED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            findings_count=findings_count,
            duration_seconds=duration_seconds,
            detectors_run=detectors_run
        )
        self._publish_event(f"analysis.{scan_id}.completed", event.to_dict())
        logger.info(f"Published analysis completed: {scan_id} ({findings_count} findings)")

    def publish_analysis_failed(
        self,
        scan_id: str,
        error: str
    ) -> None:
        """
        Publish analysis failed event.

        Args:
            scan_id: Unique scan identifier
            error: Error message
        """
        event = AnalysisFailedEvent(
            event_type=EventType.ANALYSIS_FAILED.value,
            timestamp=get_ist_now().isoformat(),
            scan_id=scan_id,
            error=error
        )
        self._publish_event(f"analysis.{scan_id}.failed", event.to_dict())
        logger.error(f"Published analysis failed: {scan_id} - {error}")
