# OpenEASD

**Open Source External Attack Surface Detection** - A powerful API-based platform for detecting and managing your external attack surface. It combines multiple security tools to provide a comprehensive view of your assets and potential vulnerabilities.

## Features

- **REST API**: Full CRUD API for domain and scan management
- **Async Scanning**: Non-blocking scan execution via ZeroMQ job queue
- **Attack Surface Discovery**: Uses Subfinder to discover subdomains
- **Port Scanning**: Uses Naabu for fast port discovery
- **DNS Resolution**: Uses Dnsx for DNS validation
- **Web Probing**: Uses Httpx to gather HTTP service information
- **Vulnerability Detection**: Analysis engine with risk scoring (0-100)
- **Service Detection**: Nmap for service identification and CVE detection

## Architecture

OpenEASD uses a 6-layer API-only architecture:

```
Layer 1: API Layer       - FastAPI REST endpoints (Full CRUD)
Layer 2: Orchestrator Layer   - Business logic
Layer 3: Messaging Layer - ZeroMQ job queue for async processing
Layer 4: Analysis Layer  - Vulnerability detection and risk scoring
Layer 5: Tools Layer     - Security tool execution (Subfinder, Naabu, etc.)
Layer 6: Database Layer  - SQLite with SQLModel ORM
```

## Getting Started

### Prerequisites

- Python 3.11+
- External tools installed and in PATH:
  - subfinder
  - naabu
  - dnsx
  - httpx
  - nmap (optional, for service detection)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/openeasd.git
cd openeasd
```

2. Install dependencies using uv:
```bash
uv sync
```

### Running the Application

**Option 1: Single Command (Recommended for Development)**

```bash
# Start both API server and worker with one command
python run_dev.py

# With custom port
python run_dev.py --port 8080

# With multiple workers for higher throughput
python run_dev.py --workers 3
```

Press `Ctrl+C` to stop all processes.

**Option 2: Separate Processes (Production)**

```bash
# Terminal 1: Start API server
python openeasd.py --port 8000

# Terminal 2: Start worker
python -m workers.scan_worker
```

The API will be available at `http://localhost:8000`

### API Documentation

Once the server is running, access the interactive API docs:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Usage

### Health Check
```bash
curl http://localhost:8000/api/v1/health
```

### Domain Management

```bash
# Create a domain
curl -X POST http://localhost:8000/api/v1/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_primary": true}'

# List domains
curl http://localhost:8000/api/v1/domains

# Get domain details
curl http://localhost:8000/api/v1/domains/example.com

# Update domain
curl -X PUT http://localhost:8000/api/v1/domains/example.com \
  -H "Content-Type: application/json" \
  -d '{"is_primary": false}'

# Delete domain
curl -X DELETE http://localhost:8000/api/v1/domains/example.com
```

### Scan Operations

```bash
# Start a scan (async - returns immediately)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Response: {"scan_id": "abc123", "status": "pending", ...}

# Poll scan status
curl http://localhost:8000/api/v1/scans/abc123

# Get scan results (when status is "completed")
curl http://localhost:8000/api/v1/scans/abc123/results

# List all scans
curl http://localhost:8000/api/v1/scans
```

### Findings

```bash
# List all findings
curl http://localhost:8000/api/v1/findings

# Get finding details
curl http://localhost:8000/api/v1/findings/{finding_id}

# Get statistics
curl http://localhost:8000/api/v1/findings/statistics/summary
```

## Async Scan Flow

1. **POST /api/v1/scans** - Creates scan record, pushes job to queue, returns 202 Accepted
2. **Worker** - Pulls job, executes tools (Subfinder, Dnsx, Naabu, Httpx), saves results
3. **Poll GET /api/v1/scans/{id}** - Check status (pending → running → completed)
4. **GET /api/v1/scans/{id}/results** - Retrieve full scan results

## Running Multiple Workers

For higher throughput, run multiple worker instances:

```bash
# Terminal 1
python -m workers.scan_worker

# Terminal 2
python -m workers.scan_worker

# Terminal 3
python -m workers.scan_worker
```

ZeroMQ automatically distributes jobs across workers.

## Project Structure

```
OpenEASD/
├── src/
│   ├── api/          # REST API (FastAPI)
│   ├── services/     # Business logic
│   ├── messaging/    # ZeroMQ job queue
│   ├── analysis/     # Vulnerability detection
│   ├── tools/        # Security tool wrappers
│   └── data/         # Database (SQLModel)
├── workers/          # Background job processors
├── tests/            # Test suite
├── run_dev.py        # Development runner (API + workers)
├── openeasd.py       # API server entry point
└── pyproject.toml    # Dependencies
```

## Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=src --cov-report=term-missing
```

## Documentation

- [DESIGN.md](DESIGN.md) - Architecture overview
- [CLAUDE.md](CLAUDE.md) - Development guide
- [docs/LAYER_ARCHITECTURE.md](docs/LAYER_ARCHITECTURE.md) - Detailed layer documentation

## License

MIT License
