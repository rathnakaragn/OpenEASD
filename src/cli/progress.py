"""
Real-time progress display for CLI using ZeroMQ events.

Provides live updates during scan execution by subscribing to events.
"""

import threading
import time
from typing import Optional, Dict, Any
import click
from src.messaging.subscriber import EventSubscriber


class ScanProgressDisplay:
    """
    Real-time progress display for scan operations.

    Subscribes to scan/tool/analysis events and displays progress in real-time.
    """

    def __init__(self, ipc_path: str = "/tmp/openeasd-events.ipc"):
        """
        Initialize progress display.

        Args:
            ipc_path: Path to IPC socket for event bus
        """
        self.ipc_path = ipc_path
        self.subscriber: Optional[EventSubscriber] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.scan_id: Optional[str] = None

        # Track progress state
        self.current_tool: Optional[str] = None
        self.tool_start_time: Optional[float] = None
        self.findings_count = 0

    def start(self, scan_id: str):
        """
        Start displaying progress for a scan.

        Args:
            scan_id: Scan ID to monitor
        """
        self.scan_id = scan_id
        self.running = True

        # Create subscriber
        self.subscriber = EventSubscriber(
            self.ipc_path,
            topics=[f"scan.{scan_id}.*", "tool.*", "finding.*", "analysis.*"]
        )

        # Start background thread
        self.thread = threading.Thread(target=self._event_loop, daemon=True)
        self.thread.start()

        # Give subscriber time to connect
        time.sleep(0.05)

    def stop(self):
        """Stop displaying progress."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        if self.subscriber:
            self.subscriber.unsubscribe()

    def _event_loop(self):
        """Background thread that polls for events and displays them."""
        while self.running:
            try:
                event = self.subscriber.poll(timeout_ms=100)
                if event:
                    self._handle_event(event)
            except Exception as e:
                click.echo(f"\n[!] Error in progress display: {e}", err=True)

    def _handle_event(self, event: Dict[str, Any]):
        """
        Handle incoming event and display progress.

        Args:
            event: Event dictionary
        """
        event_type = event.get('event_type', '')

        if event_type == 'scan.started':
            self._handle_scan_started(event)
        elif event_type == 'scan.tool.started':
            self._handle_tool_started(event)
        elif event_type == 'scan.tool.completed':
            self._handle_tool_completed(event)
        elif event_type == 'scan.tool.failed':
            self._handle_tool_failed(event)
        elif event_type == 'finding.discovered':
            self._handle_finding_discovered(event)
        elif event_type == 'analysis.started':
            self._handle_analysis_started(event)
        elif event_type == 'analysis.completed':
            self._handle_analysis_completed(event)
        elif event_type == 'scan.completed':
            self._handle_scan_completed(event)
        elif event_type == 'scan.failed':
            self._handle_scan_failed(event)

    def _handle_scan_started(self, event: Dict[str, Any]):
        """Handle scan started event."""
        domain = event.get('domain', 'unknown')
        scan_type = event.get('scan_type', 'unknown')
        click.echo(f"\n[*] Scan started: {domain} ({scan_type})")

    def _handle_tool_started(self, event: Dict[str, Any]):
        """Handle tool started event."""
        tool_name = event.get('tool_name', 'unknown')
        target_count = event.get('target_count')

        self.current_tool = tool_name
        self.tool_start_time = time.time()

        if target_count:
            click.echo(f"[*] Running {tool_name} on {target_count} targets...")
        else:
            click.echo(f"[*] Running {tool_name}...")

    def _handle_tool_completed(self, event: Dict[str, Any]):
        """Handle tool completed event."""
        tool_name = event.get('tool_name', 'unknown')
        results_count = event.get('results_count', 0)
        duration = event.get('duration_seconds', 0.0)

        click.echo(f"[+] {tool_name} completed: {results_count} results in {duration:.2f}s")

        self.current_tool = None
        self.tool_start_time = None

    def _handle_tool_failed(self, event: Dict[str, Any]):
        """Handle tool failed event."""
        tool_name = event.get('tool_name', 'unknown')
        error = event.get('error', 'unknown error')

        click.echo(f"[!] {tool_name} failed: {error}", err=True)

        self.current_tool = None
        self.tool_start_time = None

    def _handle_finding_discovered(self, event: Dict[str, Any]):
        """Handle finding discovered event."""
        finding_type = event.get('finding_type', 'unknown')
        severity = event.get('severity', 'info')
        affected_asset = event.get('affected_asset', 'unknown')
        risk_score = event.get('risk_score', 0)

        self.findings_count += 1

        # Color based on severity
        severity_colors = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'white'
        }
        color = severity_colors.get(severity, 'white')

        click.echo(
            f"[!] Finding #{self.findings_count}: "
            f"{click.style(severity.upper(), fg=color)} - "
            f"{finding_type} on {affected_asset} "
            f"(risk: {risk_score})"
        )

    def _handle_analysis_started(self, event: Dict[str, Any]):
        """Handle analysis started event."""
        detector_count = event.get('detector_count', 0)
        click.echo(f"\n[*] Analysis started with {detector_count} detectors...")

    def _handle_analysis_completed(self, event: Dict[str, Any]):
        """Handle analysis completed event."""
        findings_count = event.get('findings_count', 0)
        duration = event.get('duration_seconds', 0.0)

        click.echo(f"[+] Analysis completed: {findings_count} findings in {duration:.2f}s")

    def _handle_scan_completed(self, event: Dict[str, Any]):
        """Handle scan completed event."""
        findings_count = event.get('findings_count', 0)
        duration = event.get('duration_seconds', 0.0)
        tools_executed = event.get('tools_executed', [])

        click.echo(f"\n[✓] Scan completed successfully!")
        click.echo(f"    Duration: {duration:.2f}s")
        click.echo(f"    Tools: {', '.join(tools_executed)}")
        click.echo(f"    Findings: {findings_count}")

    def _handle_scan_failed(self, event: Dict[str, Any]):
        """Handle scan failed event."""
        error = event.get('error', 'unknown error')

        click.echo(f"\n[✗] Scan failed: {error}", err=True)


class ContextProgressDisplay:
    """
    Context manager for scan progress display.

    Usage:
        with ContextProgressDisplay(scan_id) as progress:
            # Scan runs here
            # Progress is displayed in background
    """

    def __init__(self, scan_id: str, ipc_path: str = "/tmp/openeasd-events.ipc"):
        """
        Initialize context progress display.

        Args:
            scan_id: Scan ID to monitor
            ipc_path: Path to IPC socket
        """
        self.display = ScanProgressDisplay(ipc_path)
        self.scan_id = scan_id

    def __enter__(self):
        """Start progress display."""
        self.display.start(self.scan_id)
        return self.display

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop progress display."""
        self.display.stop()
        return False
