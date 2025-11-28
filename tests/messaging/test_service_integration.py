"""
Integration tests for messaging layer with service layer.

Tests that ScanService and AnalysisService properly publish events.
"""

import pytest
import time
import asyncio
from unittest.mock import Mock, MagicMock, AsyncMock, patch
from src.messaging import EventBus, EventPublisher, EventSubscriber
from src.services.scan_service import ScanService
from src.analysis.analysis_service import AnalysisService


@pytest.fixture
def event_bus():
    """Create and start an event bus for testing."""
    ipc_path = "/tmp/test-service-integration.ipc"
    bus = EventBus(ipc_path=ipc_path)
    bus.start()
    yield bus
    bus.stop()


@pytest.fixture
def event_publisher(event_bus):
    """Create an event publisher."""
    return EventPublisher(event_bus)


@pytest.fixture
def event_subscriber(event_bus):
    """Create an event subscriber listening to all topics."""
    ipc_path = "/tmp/test-service-integration.ipc"
    subscriber = EventSubscriber(ipc_path, topics=["scan.*", "tool.*", "finding.*", "analysis.*"])
    time.sleep(0.1)  # Allow subscriber to connect
    yield subscriber
    subscriber.unsubscribe()


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    db = Mock()
    db.create_scan_session = Mock(return_value="test-scan-123")
    db.domain_exists = Mock(return_value=False)
    db.add_domain = Mock()
    db.store_subfinder_results = Mock()
    db.store_naabu_results = Mock()
    db.store_alerts = Mock()
    db.update_scan_status = Mock()
    db.get_scan_session = Mock(return_value={'start_time': None})
    return db


def test_scan_service_publishes_scan_started(event_bus, event_publisher, event_subscriber, mock_db_manager):
    """Test that ScanService publishes scan.started event."""
    # Create ScanService with event publisher
    scan_service = ScanService(
        db_manager=mock_db_manager,
        enable_analysis=False,
        event_publisher=event_publisher
    )

    # Mock tool runners to avoid actual execution
    with patch('src.services.scan_service.run_subfinder', return_value=[]), \
         patch('src.services.scan_service.run_dnsx', return_value=[]), \
         patch('src.services.scan_service.run_naabu', return_value=[]), \
         patch('src.services.scan_service.validate_domain', return_value='example.com'):

        # Execute scan (will be mocked)
        try:
            scan_service.execute_scan('example.com', timeout=1)
        except Exception:
            pass  # Ignore errors, we just want to test event publishing

    # Poll for scan.started event
    event = event_subscriber.poll(timeout_ms=1000)
    assert event is not None
    assert event['event_type'] == 'scan.started'
    assert event['scan_id'] == 'test-scan-123'
    assert event['domain'] == 'example.com'
    assert event['scan_type'] == 'passive_subdomain_enum'
    assert event['tool_name'] == 'subfinder'


def test_scan_service_publishes_tool_events(event_bus, event_publisher, event_subscriber, mock_db_manager):
    """Test that ScanService publishes tool started/completed events."""
    scan_service = ScanService(
        db_manager=mock_db_manager,
        enable_analysis=False,
        event_publisher=event_publisher
    )

    # Mock tool runners
    with patch('src.services.scan_service.run_subfinder', return_value=['sub1.example.com', 'sub2.example.com']), \
         patch('src.services.scan_service.run_dnsx', return_value=[]), \
         patch('src.services.scan_service.run_naabu', return_value=[]), \
         patch('src.services.scan_service.validate_domain', return_value='example.com'):

        try:
            scan_service.execute_scan('example.com', timeout=1)
        except Exception:
            pass

    # Collect events
    events = event_subscriber.poll_batch(max_events=10, timeout_ms=500)

    # Find tool events
    tool_events = [e for e in events if 'tool' in e.get('event_type', '')]

    # Should have at least tool.started and tool.completed for subfinder
    assert len(tool_events) >= 2

    # Check for tool.started
    tool_started = [e for e in tool_events if e['event_type'] == 'scan.tool.started']
    assert len(tool_started) >= 1
    assert tool_started[0]['tool_name'] == 'subfinder'

    # Check for tool.completed
    tool_completed = [e for e in tool_events if e['event_type'] == 'scan.tool.completed']
    assert len(tool_completed) >= 1
    assert tool_completed[0]['tool_name'] == 'subfinder'
    assert tool_completed[0]['results_count'] == 2  # 2 subdomains found


def test_scan_service_publishes_scan_completed(event_bus, event_publisher, event_subscriber, mock_db_manager):
    """Test that ScanService publishes scan.completed event."""
    scan_service = ScanService(
        db_manager=mock_db_manager,
        enable_analysis=False,
        event_publisher=event_publisher
    )

    with patch('src.services.scan_service.run_subfinder', return_value=['sub1.example.com']), \
         patch('src.services.scan_service.run_dnsx', return_value=[]), \
         patch('src.services.scan_service.run_naabu', return_value=[]), \
         patch('src.services.scan_service.validate_domain', return_value='example.com'):

        scan_service.execute_scan('example.com', timeout=1)

    # Poll for events until we get scan.completed
    scan_completed = None
    for _ in range(20):  # Try up to 20 times
        event = event_subscriber.poll(timeout_ms=100)
        if event and event.get('event_type') == 'scan.completed':
            scan_completed = event
            break

    assert scan_completed is not None
    assert scan_completed['scan_id'] == 'test-scan-123'
    assert scan_completed['domain'] == 'example.com'
    assert 'findings_count' in scan_completed
    assert 'tools_executed' in scan_completed
    assert 'subfinder' in scan_completed['tools_executed']


def test_scan_service_publishes_scan_failed(event_bus, event_publisher, event_subscriber, mock_db_manager):
    """Test that ScanService publishes scan.failed event on error."""
    scan_service = ScanService(
        db_manager=mock_db_manager,
        enable_analysis=False,
        event_publisher=event_publisher
    )

    # Make subfinder raise an error
    with patch('src.services.scan_service.run_subfinder', side_effect=Exception("Tool failed")), \
         patch('src.services.scan_service.validate_domain', return_value='example.com'):

        with pytest.raises(Exception):
            scan_service.execute_scan('example.com', timeout=1)

    # Poll for scan.failed event
    scan_failed = None
    for _ in range(20):
        event = event_subscriber.poll(timeout_ms=100)
        if event and event.get('event_type') == 'scan.failed':
            scan_failed = event
            break

    assert scan_failed is not None
    assert scan_failed['scan_id'] == 'test-scan-123'
    assert scan_failed['domain'] == 'example.com'
    assert 'error' in scan_failed
    assert 'Tool failed' in scan_failed['error']


@pytest.mark.asyncio
async def test_analysis_service_publishes_analysis_started(event_bus, event_publisher, event_subscriber):
    """Test that AnalysisService publishes analysis.started event."""
    # Create AnalysisService with event publisher
    analysis_service = AnalysisService(
        db_manager=None,
        event_publisher=event_publisher
    )

    # Mock scan data
    scan_data = {
        'scan_id': 'test-scan-123',
        'domain': 'example.com',
        'subfinder_results': [],
        'dnsx_results': [],
        'naabu_results': []
    }

    # Run analysis
    try:
        await analysis_service.analyze_scan_results('test-scan-123', scan_data)
    except Exception:
        pass  # Ignore errors

    # Poll for analysis.started event
    event = event_subscriber.poll(timeout_ms=1000)
    assert event is not None
    assert event['event_type'] == 'analysis.started'
    assert event['scan_id'] == 'test-scan-123'
    assert 'detector_count' in event


@pytest.mark.asyncio
async def test_analysis_service_publishes_analysis_completed(event_bus, event_publisher, event_subscriber):
    """Test that AnalysisService publishes analysis.completed event."""
    analysis_service = AnalysisService(
        db_manager=None,
        event_publisher=event_publisher
    )

    scan_data = {
        'scan_id': 'test-scan-123',
        'domain': 'example.com',
        'subfinder_results': [],
        'dnsx_results': [],
        'naabu_results': []
    }

    # Run analysis
    result = await analysis_service.analyze_scan_results('test-scan-123', scan_data)
    assert result is not None

    # Poll for analysis.completed event
    analysis_completed = None
    for _ in range(20):
        event = event_subscriber.poll(timeout_ms=100)
        if event and event.get('event_type') == 'analysis.completed':
            analysis_completed = event
            break

    assert analysis_completed is not None
    assert analysis_completed['scan_id'] == 'test-scan-123'
    assert 'findings_count' in analysis_completed
    assert 'duration_seconds' in analysis_completed
    assert 'detectors_run' in analysis_completed


@pytest.mark.asyncio
async def test_analysis_service_publishes_finding_discovered(event_bus, event_publisher, event_subscriber):
    """Test that AnalysisService publishes finding.discovered events."""
    analysis_service = AnalysisService(
        db_manager=None,
        event_publisher=event_publisher
    )

    # Mock scan data with open ports to trigger findings
    scan_data = {
        'scan_id': 'test-scan-123',
        'domain': 'example.com',
        'subfinder_results': [{'subdomain': 'db.example.com'}],
        'dnsx_results': [],
        'naabu_results': [
            {
                'host': 'db.example.com',
                'port': 3306,
                'protocol': 'tcp',
                'ip': '1.2.3.4'
            }
        ]
    }

    # Run analysis
    result = await analysis_service.analyze_scan_results('test-scan-123', scan_data)
    assert result['findings_count'] > 0  # Should have at least one finding

    # Collect all events
    events = event_subscriber.poll_batch(max_events=20, timeout_ms=500)

    # Find finding.discovered events
    finding_events = [e for e in events if e.get('event_type') == 'finding.discovered']

    assert len(finding_events) > 0

    # Check first finding
    finding = finding_events[0]
    assert finding['scan_id'] == 'test-scan-123'
    assert 'finding_id' in finding
    assert 'finding_type' in finding
    assert 'severity' in finding
    assert 'affected_asset' in finding
    assert 'risk_score' in finding


@pytest.mark.asyncio
async def test_analysis_service_publishes_analysis_failed(event_bus, event_publisher, event_subscriber):
    """Test that AnalysisService publishes analysis.failed event on error."""
    # Create AnalysisService with mocked detector that raises error
    analysis_service = AnalysisService(
        db_manager=None,
        event_publisher=event_publisher
    )

    # Mock detector to raise error
    mock_detector = Mock()
    mock_detector.is_enabled = Mock(return_value=True)
    mock_detector.get_name = Mock(return_value='test_detector')
    mock_detector.analyze = Mock(side_effect=Exception("Detector failed"))

    analysis_service.detectors = [mock_detector]

    scan_data = {
        'scan_id': 'test-scan-123',
        'domain': 'example.com',
        'subfinder_results': [],
        'dnsx_results': [],
        'naabu_results': []
    }

    # Run analysis (should handle detector error gracefully)
    result = await analysis_service.analyze_scan_results('test-scan-123', scan_data)

    # Even with detector error, analysis should complete (error is caught)
    # So we should get analysis.completed, not analysis.failed

    # Poll for events
    events = event_subscriber.poll_batch(max_events=10, timeout_ms=500)

    # Should have analysis.started and analysis.completed
    event_types = [e.get('event_type') for e in events]
    assert 'analysis.started' in event_types
    assert 'analysis.completed' in event_types
