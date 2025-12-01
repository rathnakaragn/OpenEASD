
import pytest
import threading
import time
from unittest.mock import MagicMock, patch
from src.cli.progress import ScanProgressDisplay, ContextProgressDisplay


@pytest.fixture
def mock_subscriber():
    with patch('src.cli.progress.EventSubscriber') as MockSubscriber:
        yield MockSubscriber


@pytest.fixture
def mock_click():
    with patch('src.cli.progress.click') as MockClick:
        yield MockClick


class TestScanProgressDisplay:

    def test_init(self):
        display = ScanProgressDisplay()
        assert display.ipc_path == "/tmp/openeasd-events.ipc"
        assert display.subscriber is None
        assert not display.running
        assert display.thread is None
        assert display.scan_id is None
        assert display.current_tool is None
        assert display.tool_start_time is None
        assert display.findings_count == 0

    def test_init_custom_ipc_path(self):
        display = ScanProgressDisplay(ipc_path="/custom/path.ipc")
        assert display.ipc_path == "/custom/path.ipc"

    def test_start_and_stop(self, mock_subscriber):
        display = ScanProgressDisplay()
        test_scan_id = "test-scan-123"

        display.start(test_scan_id)

        assert display.running
        assert display.scan_id == test_scan_id
        mock_subscriber.assert_called_once_with(
            "/tmp/openeasd-events.ipc",
            topics=[f"scan.{test_scan_id}.*", "tool.*", "finding.*", "analysis.*"]
        )
        assert isinstance(display.thread, threading.Thread)
        assert display.thread.is_alive()

        display.stop()
        assert not display.running
        assert not display.thread.is_alive()
        mock_subscriber.return_value.unsubscribe.assert_called_once()

    def test_event_loop_handles_event(self, mock_subscriber):
        display = ScanProgressDisplay()
        display.scan_id = "test-scan-123"
        display.subscriber = mock_subscriber.return_value
        display.subscriber.poll.side_effect = [{'event_type': 'scan.started', 'domain': 'example.com'}, None]

        with patch.object(display, '_handle_event') as mock_handle_event:
            display.running = True
            display._event_loop()
            mock_handle_event.assert_called_once_with({'event_type': 'scan.started', 'domain': 'example.com'})

    def test_event_loop_handles_exception(self, mock_subscriber, mock_click):
        display = ScanProgressDisplay()
        display.scan_id = "test-scan-123"
        display.subscriber = mock_subscriber.return_value
        display.subscriber.poll.side_effect = Exception("Test event loop error")

        display.running = True
        display._event_loop()
        mock_click.echo.assert_called_with("\n[!] Error in progress display: Test event loop error", err=True)

    def test_handle_event_dispatch(self, mock_click):
        display = ScanProgressDisplay()

        event_handlers = {
            'scan.started': '_handle_scan_started',
            'scan.tool.started': '_handle_tool_started',
            'scan.tool.completed': '_handle_tool_completed',
            'scan.tool.failed': '_handle_tool_failed',
            'finding.discovered': '_handle_finding_discovered',
            'analysis.started': '_handle_analysis_started',
            'analysis.completed': '_handle_analysis_completed',
            'scan.completed': '_handle_scan_completed',
            'scan.failed': '_handle_scan_failed',
        }

        for event_type, handler_name in event_handlers.items():
            with patch.object(display, handler_name) as mock_handler:
                event = {'event_type': event_type}
                display._handle_event(event)
                mock_handler.assert_called_once_with(event)

    def test_handle_scan_started(self, mock_click):
        display = ScanProgressDisplay()
        event = {'domain': 'example.com', 'scan_type': 'passive'}
        display._handle_scan_started(event)
        mock_click.echo.assert_called_once_with("\n[*] Scan started: example.com (passive)")

    def test_handle_tool_started(self, mock_click):
        display = ScanProgressDisplay()
        event = {'tool_name': 'subfinder', 'target_count': 10}
        display._handle_tool_started(event)
        mock_click.echo.assert_called_once_with("[*] Running subfinder on 10 targets...")
        assert display.current_tool == 'subfinder'
        assert display.tool_start_time is not None

    def test_handle_tool_started_no_target_count(self, mock_click):
        display = ScanProgressDisplay()
        event = {'tool_name': 'nmap'}
        display._handle_tool_started(event)
        mock_click.echo.assert_called_once_with("[*] Running nmap...")
        assert display.current_tool == 'nmap'
        assert display.tool_start_time is not None

    def test_handle_tool_completed(self, mock_click):
        display = ScanProgressDisplay()
        display.current_tool = "subfinder"
        display.tool_start_time = time.time() - 5  # Simulate 5 seconds duration
        event = {'tool_name': 'subfinder', 'results_count': 50, 'duration_seconds': 5.0}
        display._handle_tool_completed(event)
        mock_click.echo.assert_called_once_with("[+] subfinder completed: 50 results in 5.00s")
        assert display.current_tool is None
        assert display.tool_start_time is None

    def test_handle_tool_failed(self, mock_click):
        display = ScanProgressDisplay()
        display.current_tool = "naabu"
        display.tool_start_time = time.time()
        event = {'tool_name': 'naabu', 'error': 'Network unreachable'}
        display._handle_tool_failed(event)
        mock_click.echo.assert_called_once_with("[!] naabu failed: Network unreachable", err=True)
        assert display.current_tool is None
        assert display.tool_start_time is None

    def test_handle_finding_discovered(self, mock_click):
        display = ScanProgressDisplay()
        display.findings_count = 0
        event = {'finding_type': 'port_open', 'severity': 'high', 'affected_asset': 'example.com', 'risk_score': 75}
        display._handle_finding_discovered(event)
        assert display.findings_count == 1
        mock_click.echo.assert_called_once()
        mock_click.style.assert_called_once_with('HIGH', fg='red')

    @pytest.mark.parametrize("severity,expected_color", [
        ('critical', 'red'), ('high', 'red'), ('medium', 'yellow'),
        ('low', 'blue'), ('info', 'white'), ('unknown', 'white')
    ])
    def test_handle_finding_discovered_colors(self, mock_click, severity, expected_color):
        display = ScanProgressDisplay()
        event = {'finding_type': 'test', 'severity': severity, 'affected_asset': 'a.com', 'risk_score': 10}
        display._handle_finding_discovered(event)
        mock_click.style.assert_called_once_with(severity.upper(), fg=expected_color)

    def test_handle_analysis_started(self, mock_click):
        display = ScanProgressDisplay()
        event = {'detector_count': 5}
        display._handle_analysis_started(event)
        mock_click.echo.assert_called_once_with("\n[*] Analysis started with 5 detectors...")

    def test_handle_analysis_completed(self, mock_click):
        display = ScanProgressDisplay()
        event = {'findings_count': 20, 'duration_seconds': 10.5}
        display._handle_analysis_completed(event)
        mock_click.echo.assert_called_once_with("[+] Analysis completed: 20 findings in 10.50s")

    def test_handle_scan_completed(self, mock_click):
        display = ScanProgressDisplay()
        event = {'findings_count': 30, 'duration_seconds': 120.0, 'tools_executed': ['subfinder', 'naabu']}
        display._handle_scan_completed(event)
        mock_click.echo.assert_any_call("\n[✓] Scan completed successfully!")
        mock_click.echo.assert_any_call("    Duration: 120.00s")
        mock_click.echo.assert_any_call("    Tools: subfinder, naabu")
        mock_click.echo.assert_any_call("    Findings: 30")

    def test_handle_scan_failed(self, mock_click):
        display = ScanProgressDisplay()
        event = {'error': 'Critical system error'}
        display._handle_scan_failed(event)
        mock_click.echo.assert_called_once_with("\n[✗] Scan failed: Critical system error", err=True)


class TestContextProgressDisplay:

    def test_context_manager(self, mock_subscriber, mock_click):
        test_scan_id = "context-scan-456"
        with patch.object(ScanProgressDisplay, 'start') as mock_start, \
             patch.object(ScanProgressDisplay, 'stop') as mock_stop:
            with ContextProgressDisplay(test_scan_id) as display_instance:
                mock_start.assert_called_once_with(test_scan_id)
                assert isinstance(display_instance, ScanProgressDisplay)
            mock_stop.assert_called_once()

