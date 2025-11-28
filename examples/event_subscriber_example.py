#!/usr/bin/env python3
"""
Example: Subscribe to OpenEASD events and process them in real-time.

This example shows how to:
1. Connect to the OpenEASD EventBus
2. Subscribe to specific event topics
3. Process events as they arrive
4. Display real-time scan progress

Usage:
    python examples/event_subscriber_example.py

Make sure OpenEASD API or CLI is running with EventBus enabled.
"""

import sys
import time
from datetime import datetime
from src.messaging.subscriber import EventSubscriber
from src.messaging.manager import EventBusManager


class EventMonitor:
    """Monitor and display OpenEASD events in real-time."""

    def __init__(self, ipc_path="/tmp/openeasd-events.ipc"):
        """
        Initialize event monitor.

        Args:
            ipc_path: Path to EventBus IPC socket
        """
        self.ipc_path = ipc_path
        self.subscriber = None
        self.stats = {
            'total_events': 0,
            'scans_active': set(),
            'scans_completed': 0,
            'scans_failed': 0,
            'findings_discovered': 0,
            'tools_executed': {},
        }

    def connect(self):
        """Connect to EventBus."""
        print(f"Connecting to EventBus at {self.ipc_path}...")

        try:
            # Subscribe to all event types
            self.subscriber = EventSubscriber(
                self.ipc_path,
                topics=["scan.*", "tool.*", "finding.*", "analysis.*"]
            )
            print("✅ Connected! Listening for events...\n")
            return True
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            print("\nMake sure OpenEASD API or CLI is running:")
            print("  API: uvicorn src.api.main:app --port 8000")
            print("  CLI: python openeasd.py scan example.com")
            return False

    def run(self):
        """Main event loop - poll and process events."""
        if not self.connect():
            return

        print("=" * 80)
        print("LIVE EVENT STREAM - Press Ctrl+C to stop")
        print("=" * 80)
        print()

        try:
            while True:
                # Poll for events (1 second timeout)
                event = self.subscriber.poll(timeout_ms=1000)

                if event:
                    self.process_event(event)

                # Show stats every 10 seconds
                if self.stats['total_events'] > 0 and self.stats['total_events'] % 10 == 0:
                    self.show_stats()

        except KeyboardInterrupt:
            print("\n\n" + "=" * 80)
            print("Shutting down...")
            self.show_final_stats()

        finally:
            if self.subscriber:
                self.subscriber.unsubscribe()
                print("✅ Disconnected from EventBus")

    def process_event(self, event):
        """
        Process a single event.

        Args:
            event: Event dictionary
        """
        self.stats['total_events'] += 1
        event_type = event.get('event_type', 'unknown')
        timestamp = datetime.fromisoformat(event.get('timestamp', ''))

        # Format timestamp
        time_str = timestamp.strftime('%H:%M:%S')

        # Handle different event types
        if event_type == 'scan.started':
            self.handle_scan_started(event, time_str)
        elif event_type == 'scan.completed':
            self.handle_scan_completed(event, time_str)
        elif event_type == 'scan.failed':
            self.handle_scan_failed(event, time_str)
        elif event_type == 'scan.tool.started':
            self.handle_tool_started(event, time_str)
        elif event_type == 'scan.tool.completed':
            self.handle_tool_completed(event, time_str)
        elif event_type == 'scan.tool.failed':
            self.handle_tool_failed(event, time_str)
        elif event_type == 'finding.discovered':
            self.handle_finding_discovered(event, time_str)
        elif event_type == 'analysis.started':
            self.handle_analysis_started(event, time_str)
        elif event_type == 'analysis.completed':
            self.handle_analysis_completed(event, time_str)
        elif event_type == 'analysis.failed':
            self.handle_analysis_failed(event, time_str)
        else:
            print(f"[{time_str}] {event_type}: {event}")

    def handle_scan_started(self, event, time_str):
        """Handle scan.started event."""
        scan_id = event['scan_id'][:8]
        domain = event['domain']
        scan_type = event['scan_type']

        self.stats['scans_active'].add(event['scan_id'])

        print(f"[{time_str}] 🚀 SCAN STARTED")
        print(f"           Scan ID: {scan_id}...")
        print(f"           Domain:  {domain}")
        print(f"           Type:    {scan_type}")
        print()

    def handle_scan_completed(self, event, time_str):
        """Handle scan.completed event."""
        scan_id = event['scan_id'][:8]
        domain = event['domain']
        findings = event['findings_count']
        duration = event['duration_seconds']
        tools = ', '.join(event['tools_executed'])

        self.stats['scans_active'].discard(event['scan_id'])
        self.stats['scans_completed'] += 1

        print(f"[{time_str}] ✅ SCAN COMPLETED")
        print(f"           Scan ID:  {scan_id}...")
        print(f"           Domain:   {domain}")
        print(f"           Findings: {findings}")
        print(f"           Duration: {duration:.2f}s")
        print(f"           Tools:    {tools}")
        print()

    def handle_scan_failed(self, event, time_str):
        """Handle scan.failed event."""
        scan_id = event['scan_id'][:8]
        domain = event['domain']
        error = event['error']

        self.stats['scans_active'].discard(event['scan_id'])
        self.stats['scans_failed'] += 1

        print(f"[{time_str}] ❌ SCAN FAILED")
        print(f"           Scan ID: {scan_id}...")
        print(f"           Domain:  {domain}")
        print(f"           Error:   {error}")
        print()

    def handle_tool_started(self, event, time_str):
        """Handle scan.tool.started event."""
        tool = event['tool_name']
        target_count = event.get('target_count')

        if target_count:
            print(f"[{time_str}] 🔧 {tool} started on {target_count} targets")
        else:
            print(f"[{time_str}] 🔧 {tool} started")

    def handle_tool_completed(self, event, time_str):
        """Handle scan.tool.completed event."""
        tool = event['tool_name']
        results = event['results_count']
        duration = event['duration_seconds']

        # Track tool usage
        if tool not in self.stats['tools_executed']:
            self.stats['tools_executed'][tool] = 0
        self.stats['tools_executed'][tool] += 1

        print(f"[{time_str}] ✓  {tool} completed: {results} results in {duration:.2f}s")

    def handle_tool_failed(self, event, time_str):
        """Handle scan.tool.failed event."""
        tool = event['tool_name']
        error = event['error']

        print(f"[{time_str}] ⚠️  {tool} failed: {error}")

    def handle_finding_discovered(self, event, time_str):
        """Handle finding.discovered event."""
        finding_type = event['finding_type']
        severity = event['severity'].upper()
        asset = event['affected_asset']
        risk_score = event['risk_score']

        self.stats['findings_discovered'] += 1

        # Color-code by severity
        severity_symbols = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': '⚪'
        }
        symbol = severity_symbols.get(severity, '⚪')

        print(f"[{time_str}] {symbol} FINDING: {severity}")
        print(f"           Type:  {finding_type}")
        print(f"           Asset: {asset}")
        print(f"           Risk:  {risk_score}/100")

        if event.get('port'):
            print(f"           Port:  {event['port']}/{event.get('protocol', 'tcp')}")

        print()

    def handle_analysis_started(self, event, time_str):
        """Handle analysis.started event."""
        detector_count = event['detector_count']
        print(f"[{time_str}] 🔍 Analysis started with {detector_count} detectors")

    def handle_analysis_completed(self, event, time_str):
        """Handle analysis.completed event."""
        findings = event['findings_count']
        duration = event['duration_seconds']
        detectors = ', '.join(event['detectors_run'])

        print(f"[{time_str}] ✓  Analysis completed: {findings} findings in {duration:.2f}s")
        print(f"           Detectors: {detectors}")
        print()

    def handle_analysis_failed(self, event, time_str):
        """Handle analysis.failed event."""
        error = event['error']
        print(f"[{time_str}] ⚠️  Analysis failed: {error}")
        print()

    def show_stats(self):
        """Show current statistics."""
        print()
        print("-" * 80)
        print("STATISTICS")
        print("-" * 80)
        print(f"Total Events:      {self.stats['total_events']}")
        print(f"Active Scans:      {len(self.stats['scans_active'])}")
        print(f"Completed Scans:   {self.stats['scans_completed']}")
        print(f"Failed Scans:      {self.stats['scans_failed']}")
        print(f"Findings:          {self.stats['findings_discovered']}")
        if self.stats['tools_executed']:
            print("\nTools Executed:")
            for tool, count in self.stats['tools_executed'].items():
                print(f"  {tool}: {count}")
        print("-" * 80)
        print()

    def show_final_stats(self):
        """Show final statistics on exit."""
        print()
        print("=" * 80)
        print("FINAL STATISTICS")
        print("=" * 80)
        self.show_stats()


def main():
    """Main entry point."""
    # Check if EventBus is likely running
    print("OpenEASD Event Subscriber Example")
    print()

    monitor = EventMonitor()
    monitor.run()


if __name__ == '__main__':
    main()
