# OpenEASD Messaging Layer Documentation

**Layer 7: Real-Time Event Streaming with ZeroMQ**

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Event Schema](#event-schema)
4. [Usage Examples](#usage-examples)
5. [API Integration](#api-integration)
6. [CLI Integration](#cli-integration)
7. [Testing](#testing)

## Overview

The Messaging Layer provides real-time event streaming capabilities to OpenEASD using ZeroMQ's Pub/Sub pattern. It enables:

- **Real-time progress tracking** during scans
- **Live event streaming** to API clients via WebSocket
- **Decoupled communication** between layers
- **Non-blocking event delivery** with topic filtering

### Key Features

✅ **High Performance** - ZeroMQ IPC transport for local communication
✅ **Topic Filtering** - Subscribe to specific event types
✅ **Type-Safe** - Dataclass-based event schemas
✅ **Non-Blocking** - Timeout-based polling
✅ **Backwards Compatible** - Optional, doesn't break existing functionality
✅ **WebSocket Support** - Stream events to web clients
✅ **CLI Progress Display** - Real-time scan progress in terminal

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Messaging Layer (Layer 7)                 │
│                                                              │
│  ┌──────────────┐       ┌──────────────┐                   │
│  │  EventBus    │◄──────┤EventPublisher│                   │
│  │   (PUB)      │       │              │                   │
│  └──────┬───────┘       └──────▲───────┘                   │
│         │                      │                            │
│         │ IPC Socket          publish()                    │
│         │ (ZeroMQ)             │                            │
│         │                      │                            │
│  ┌──────▼───────┐       ┌─────┴────────┐                  │
│  │EventSubscriber◄──────┤   Services   │                   │
│  │    (SUB)     │       │              │                   │
│  └──────────────┘       └──────────────┘                   │
└─────────────────────────────────────────────────────────────┘
         │                       ▲
         │ Events                │ Events
         ▼                       │
┌─────────────────┐    ┌────────┴───────┐
│  WebSocket API  │    │  ScanService   │
│    Clients      │    │AnalysisService │
└─────────────────┘    └────────────────┘
```

### Components

**EventBus** (`src/messaging/bus.py`)
- Central Pub/Sub broker
- Single PUB socket bound to IPC
- Handles event distribution

**EventPublisher** (`src/messaging/publisher.py`)
- Type-safe publishing API
- 11 methods for different event types
- Automatic timestamp and serialization

**EventSubscriber** (`src/messaging/subscriber.py`)
- Non-blocking event reception
- Topic-based filtering with wildcards
- Batch polling support

**EventBusManager** (`src/messaging/manager.py`)
- Singleton manager for global EventBus
- Lifecycle management
- Used by CLI and API

## Event Schema

All events follow a common structure with event-specific fields:

### Base Event Structure

```python
{
    "event_type": str,      # e.g., "scan.started"
    "timestamp": str,       # ISO format timestamp (IST)
    "scan_id": str,         # UUID of the scan
    ...                     # Event-specific fields
}
```

### Event Types

#### Scan Events

**scan.started**
```json
{
    "event_type": "scan.started",
    "timestamp": "2025-11-27T10:30:00+05:30",
    "scan_id": "uuid-123",
    "domain": "example.com",
    "scan_type": "passive_subdomain_enum",
    "tool_name": "subfinder"
}
```

**scan.completed**
```json
{
    "event_type": "scan.completed",
    "timestamp": "2025-11-27T10:35:00+05:30",
    "scan_id": "uuid-123",
    "domain": "example.com",
    "findings_count": 42,
    "duration_seconds": 300.5,
    "tools_executed": ["subfinder", "dnsx", "naabu", "httpx"]
}
```

**scan.failed**
```json
{
    "event_type": "scan.failed",
    "timestamp": "2025-11-27T10:32:00+05:30",
    "scan_id": "uuid-123",
    "domain": "example.com",
    "error": "Connection timeout",
    "tool_name": "subfinder"  // Optional
}
```

#### Tool Events

**scan.tool.started**
```json
{
    "event_type": "scan.tool.started",
    "timestamp": "2025-11-27T10:30:15+05:30",
    "scan_id": "uuid-123",
    "tool_name": "subfinder",
    "domain": "example.com",
    "target_count": null  // null for initial tool, number for subsequent tools
}
```

**scan.tool.completed**
```json
{
    "event_type": "scan.tool.completed",
    "timestamp": "2025-11-27T10:32:30+05:30",
    "scan_id": "uuid-123",
    "tool_name": "subfinder",
    "domain": "example.com",
    "results_count": 25,
    "duration_seconds": 135.2
}
```

**scan.tool.failed**
```json
{
    "event_type": "scan.tool.failed",
    "timestamp": "2025-11-27T10:31:00+05:30",
    "scan_id": "uuid-123",
    "tool_name": "httpx",
    "domain": "example.com",
    "error": "Network unreachable"
}
```

#### Finding Events

**finding.discovered**
```json
{
    "event_type": "finding.discovered",
    "timestamp": "2025-11-27T10:34:00+05:30",
    "scan_id": "uuid-123",
    "finding_id": "finding-456",
    "finding_type": "database_port_exposed",
    "severity": "critical",
    "affected_asset": "db.example.com",
    "risk_score": 85,
    "port": 3306,
    "protocol": "tcp",
    "title": "MySQL database exposed to internet"
}
```

#### Analysis Events

**analysis.started**
```json
{
    "event_type": "analysis.started",
    "timestamp": "2025-11-27T10:33:00+05:30",
    "scan_id": "uuid-123",
    "detector_count": 1
}
```

**analysis.completed**
```json
{
    "event_type": "analysis.completed",
    "timestamp": "2025-11-27T10:34:30+05:30",
    "scan_id": "uuid-123",
    "findings_count": 8,
    "duration_seconds": 90.5,
    "detectors_run": ["PortVulnerabilityDetector"]
}
```

**analysis.failed**
```json
{
    "event_type": "analysis.failed",
    "timestamp": "2025-11-27T10:34:00+05:30",
    "scan_id": "uuid-123",
    "error": "Detector error: ..."
}
```

## Usage Examples

### Service Layer Integration

```python
from src.messaging.manager import EventBusManager
from src.services.scan_service import ScanService
from src.data.database.sqlmodel_manager import SQLModelManager

# Start EventBus (done automatically by CLI/API)
publisher = EventBusManager.start()

# Create ScanService with event publishing
db_manager = SQLModelManager()
db_manager.initialize()

scan_service = ScanService(
    db_manager=db_manager,
    enable_analysis=True,
    event_publisher=publisher  # Enable real-time events
)

# Execute scan - events will be published automatically
result = scan_service.execute_scan('example.com')

# Stop EventBus
EventBusManager.stop()
```

### Subscribing to Events (Python)

```python
from src.messaging.subscriber import EventSubscriber
from src.messaging.manager import EventBusManager

# Ensure EventBus is running
if not EventBusManager.is_running():
    EventBusManager.start()

# Create subscriber
subscriber = EventSubscriber(
    EventBusManager.get_ipc_path(),
    topics=["scan.*", "finding.*"]  # Subscribe to scan and finding events
)

# Poll for events
while True:
    event = subscriber.poll(timeout_ms=1000)
    if event:
        print(f"Received: {event['event_type']}")
        print(f"  Scan ID: {event.get('scan_id')}")

        if event['event_type'] == 'finding.discovered':
            print(f"  Finding: {event['finding_type']} ({event['severity']})")

# Cleanup
subscriber.unsubscribe()
```

### Batch Polling

```python
# Poll for multiple events at once
events = subscriber.poll_batch(max_events=10, timeout_ms=100)

for event in events:
    handle_event(event)
```

### Topic Filtering

```python
# Subscribe to specific scan
subscriber = EventSubscriber(
    EventBusManager.get_ipc_path(),
    topics=[f"scan.{scan_id}.*"]  # Only events for this scan
)

# Subscribe to multiple patterns
subscriber = EventSubscriber(
    EventBusManager.get_ipc_path(),
    topics=["scan.*", "tool.*", "analysis.*"]  # All workflow events
)

# Dynamic subscription
subscriber.subscribe_to_topic("finding.*")
subscriber.unsubscribe_from_topic("tool.*")
```

## API Integration

### WebSocket Endpoint

**Endpoint:** `ws://localhost:8000/api/v1/events`

**Query Parameters:**
- `topics` (optional): Comma-separated list of topic patterns
  - Default: `scan.*,tool.*,finding.*,analysis.*`

**Example Usage (JavaScript/Browser):**

```javascript
const ws = new WebSocket('ws://localhost:8000/api/v1/events?topics=scan.*,finding.*');

ws.onopen = () => {
    console.log('Connected to event stream');
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'connected') {
        console.log('WebSocket ready, subscribed to:', data.topics);
        return;
    }

    // Handle events
    switch (data.event_type) {
        case 'scan.started':
            console.log(`Scan started: ${data.domain}`);
            break;

        case 'scan.tool.completed':
            console.log(`${data.tool_name} completed: ${data.results_count} results`);
            break;

        case 'finding.discovered':
            console.log(`Finding: ${data.finding_type} (${data.severity})`);
            break;

        case 'scan.completed':
            console.log(`Scan completed: ${data.findings_count} findings`);
            break;
    }
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('WebSocket closed');
};

// Ping/pong (optional, for keeping connection alive)
setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
    }
}, 30000);
```

**Example Usage (Python with websockets):**

```python
import asyncio
import websockets
import json

async def stream_events():
    uri = "ws://localhost:8000/api/v1/events?topics=scan.*,finding.*"

    async with websockets.connect(uri) as websocket:
        # Receive connection confirmation
        message = await websocket.recv()
        data = json.loads(message)
        print(f"Connected: {data['message']}")

        # Receive events
        while True:
            message = await websocket.recv()
            event = json.loads(message)

            if event.get('event_type') == 'finding.discovered':
                print(f"Finding: {event['finding_type']} on {event['affected_asset']}")

asyncio.run(stream_events())
```

### Event Status Endpoint

Check if EventBus is running and get configuration:

```bash
curl http://localhost:8000/api/v1/events/status
```

Response:
```json
{
    "event_bus_running": true,
    "ipc_path": "/tmp/openeasd-events.ipc",
    "websocket_endpoint": "/api/v1/events",
    "supported_topics": [
        "scan.*",
        "scan.{scan_id}.*",
        "tool.*",
        "finding.*",
        "analysis.*"
    ],
    "example_url": "ws://localhost:8000/api/v1/events?topics=scan.*,finding.*"
}
```

## CLI Integration

The CLI automatically starts EventBus when launched. No configuration needed!

### Real-Time Progress Display

The `ScanProgressDisplay` class provides live updates during scans:

```python
from src.cli.progress import ContextProgressDisplay

# Use as context manager
with ContextProgressDisplay(scan_id) as progress:
    # Scan runs here
    # Progress is displayed automatically in background thread
    scan_service.execute_scan(domain)

# Progress display stops automatically when context exits
```

**Example Output:**
```
[*] Scan started: example.com (passive_subdomain_enum)
[*] Running subfinder...
[+] subfinder completed: 25 results in 135.23s
[*] Running dnsx on 25 targets...
[+] dnsx completed: 18 results in 45.12s
[*] Running naabu on 18 targets...
[+] naabu completed: 42 results in 89.45s

[*] Analysis started with 1 detectors...
[!] Finding #1: CRITICAL - database_port_exposed on db.example.com (risk: 85)
[!] Finding #2: HIGH - admin_panel_exposed on admin.example.com (risk: 75)
[+] Analysis completed: 8 findings in 12.34s

[✓] Scan completed successfully!
    Duration: 282.14s
    Tools: subfinder, dnsx, naabu
    Findings: 8
```

## Testing

### Running Tests

```bash
# All messaging tests
pytest tests/messaging/ tests/test_websocket_events.py -v

# EventBus unit tests
pytest tests/messaging/test_event_bus.py -v

# Integration tests
pytest tests/messaging/test_integration.py -v

# Service integration tests
pytest tests/messaging/test_service_integration.py -v

# WebSocket tests
pytest tests/test_websocket_events.py -v
```

### Test Coverage

- **26 passing tests**
- **EventBus**: 8 tests - initialization, start/stop, publishing, context managers
- **Pub/Sub Integration**: 8 tests - message flow, topic filtering, multiple subscribers
- **Service Integration**: 8 tests - ScanService and AnalysisService event publishing
- **WebSocket**: 2 tests - connectivity and status endpoint

### Manual Testing with wscat

Install wscat:
```bash
npm install -g wscat
```

Connect to WebSocket:
```bash
# Subscribe to all events
wscat -c "ws://localhost:8000/api/v1/events"

# Subscribe to specific topics
wscat -c "ws://localhost:8000/api/v1/events?topics=scan.*,finding.*"

# Subscribe to specific scan
wscat -c "ws://localhost:8000/api/v1/events?topics=scan.uuid-123.*"
```

Start a scan in another terminal and watch events stream in real-time!

## Configuration

### IPC Socket Path

Default: `/tmp/openeasd-events.ipc`

Change via EventBusManager:
```python
EventBusManager.start(ipc_path="/custom/path.ipc")
```

### High Water Mark

Controls max queued messages (default: 1000):

```python
from src.messaging.bus import EventBus

bus = EventBus(
    ipc_path="/tmp/openeasd-events.ipc",
    high_water_mark=2000  # Increase buffer
)
```

### Timeouts

```python
from src.messaging.subscriber import EventSubscriber

subscriber = EventSubscriber(
    ipc_path,
    topics=["scan.*"],
    recv_timeout_ms=5000  # 5 second default timeout
)

# Override per-poll
event = subscriber.poll(timeout_ms=1000)
```

## Performance Characteristics

- **Latency**: < 1ms for local IPC events
- **Throughput**: 10,000+ events/sec
- **Memory**: Minimal overhead (~10MB for EventBus)
- **CPU**: Negligible impact on scan performance

## Troubleshooting

### EventBus won't start

**Error:** "Address already in use"

**Solution:** Another instance is using the IPC socket
```bash
# Kill existing process
lsof /tmp/openeasd-events.ipc | grep python | awk '{print $2}' | xargs kill

# Or use a different path
EventBusManager.start(ipc_path="/tmp/openeasd-events-2.ipc")
```

### Not receiving events

**Check EventBus is running:**
```python
from src.messaging.manager import EventBusManager

if not EventBusManager.is_running():
    print("EventBus is not running!")
    EventBusManager.start()
```

**Check topic subscription:**
```python
# Make sure topic pattern matches event types
subscriber = EventSubscriber(path, topics=["scan.*"])  # Matches "scan.started"
subscriber = EventSubscriber(path, topics=["scan.started"])  # Only exact match
```

**Check timing:**
```python
# Give subscriber time to connect before publishing
subscriber = EventSubscriber(...)
time.sleep(0.1)  # Allow connection to establish
```

### WebSocket disconnects

**Check CORS settings** (`src/api/settings.py`):
```python
cors_allow_origins = ["*"]  # Allow all origins (development only!)
```

**Check event volume:**
- High-frequency events may overwhelm browser WebSocket
- Consider client-side throttling or server-side batching

## Future Enhancements

- [ ] Persistent event log (optional storage to database)
- [ ] Event replay capability
- [ ] Prometheus metrics for event throughput
- [ ] Multi-process EventBus (TCP transport for distributed systems)
- [ ] Event filtering by severity/priority
- [ ] Compression for large event payloads
- [ ] Authentication for WebSocket connections

---

**Last Updated:** November 27, 2025
**Version:** 1.0.0
**Status:** Production-ready ✅
