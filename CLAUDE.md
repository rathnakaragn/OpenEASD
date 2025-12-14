# CLAUDE.md - Project Guide for AI Assistants

**OpenEASD: Open Source External Attack Surface Detection**

## Quick Reference

### Current Implementation Status
- **Architecture**: 6-layer API-only design with ZeroMQ messaging
- **Model**: Single-organization architecture
- **Tech Stack**: FastAPI (Full Access), ZeroMQ, Python 3.11+, SQLite
- **Security Tools**: Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei
- **Analysis**: Automated vulnerability detection with risk scoring
- **Interface**: API-only (no CLI)
- **Job Persistence**: Database-backed job queue (survives crashes)

### 6-Layer Architecture

```
┌─────────────────────────────────────┐
│         Layer 1: API                │  FastAPI (Full CRUD)
├─────────────────────────────────────┤
│         Layer 2: Orchestrator            │  Business Logic
├─────────────────────────────────────┤
│         Layer 3: Messaging          │  ZeroMQ (PUSH/PULL)
├─────────────────────────────────────┤
│         Layer 4: Tools              │  Subfinder, Naabu, etc.
├─────────────────────────────────────┤
│         Layer 5: Analysis           │  Risk Scoring, Detectors
├─────────────────────────────────────┤
│         Layer 6: Database           │  SQLModel + SQLite
└─────────────────────────────────────┘
```

### Layer Responsibilities

**Layer 1: API** (`src/api/`)
- Full CRUD REST API (GET, POST, PUT, DELETE)
- FastAPI with Pydantic v2 schemas
- OpenAPI documentation at `/docs`

**Layer 2: Orchestrator** (`src/orchestrator/`)
- Business logic orchestration
- DomainService, ScanService, FindingsService
- ScanWorkflowOrchestrator (8-step workflow)

**Layer 3: Messaging** (`src/messaging/`)
- ZeroMQ job queue (PUSH/PULL pattern)
- Database-persisted jobs (Job model)
- Stale job recovery (30-min timeout)
- Worker coordination with ID tracking

**Layer 4: Tools** (`src/tools/`)
- External security tool execution
- Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei
- JSON output parsing

**Layer 5: Analysis** (`src/analysis/`)
- Risk scoring (0-100 scale)
- Vulnerability detection
- PortDetector, ServiceDetector

**Layer 6: Database** (`src/data/`)
- SQLite with SQLModel ORM
- Domain, Scan, Finding, Job models

## API Endpoints

```
Health
  GET    /api/v1/health

Domains (Full CRUD)
  GET    /api/v1/domains              # List domains
  POST   /api/v1/domains              # Create domain
  GET    /api/v1/domains/{domain}     # Get domain
  PUT    /api/v1/domains/{domain}     # Update domain
  DELETE /api/v1/domains/{domain}     # Delete domain

Scans (Async)
  GET    /api/v1/scans                # List scans
  POST   /api/v1/scans                # Create scan (returns 202)
  GET    /api/v1/scans/{id}           # Get scan status (poll here)
  GET    /api/v1/scans/{id}/results   # Get scan results

Findings
  GET    /api/v1/findings             # List findings
  GET    /api/v1/findings/{id}        # Get finding
  PUT    /api/v1/findings/{id}        # Update finding status
  GET    /api/v1/findings/stats       # Statistics
```

## Project Structure

```
openeasd/
├── src/
│   ├── api/                    # Layer 1: API
│   │   ├── main.py             # FastAPI app
│   │   ├── dependencies.py     # Dependency injection
│   │   ├── routes/             # Endpoint handlers
│   │   │   ├── domains.py
│   │   │   ├── scans.py
│   │   │   ├── findings.py
│   │   │   └── health.py
│   │   └── schemas/            # Pydantic models
│   │
│   ├── orchestrator/           # Layer 2: Orchestrator
│   │   ├── domain_service.py
│   │   ├── scan_service.py       # CRUD operations
│   │   ├── scan_workflow_orchestrator.py  # 8-step workflow
│   │   └── findings_service.py
│   │
│   ├── messaging/              # Layer 3: Messaging
│   │   ├── config.py           # ZeroMQ config
│   │   └── job_queue.py        # PUSH/PULL queue
│   │
│   ├── tools/                  # Layer 4: Tools
│   │   ├── subfinder/
│   │   ├── naabu/
│   │   ├── dnsx/
│   │   ├── httpx/
│   │   ├── tlsx/
│   │   ├── nmap/
│   │   └── nuclei/
│   │
│   ├── analysis/               # Layer 5: Analysis
│   │   ├── analysis_service.py
│   │   ├── scoring/
│   │   │   └── risk_scorer.py
│   │   └── detectors/
│   │       ├── port_detector.py
│   │       └── service_detector.py
│   │
│   └── data/                   # Layer 6: Database
│       ├── database/
│       │   └── sqlmodel_manager.py
│       └── models/
│           └── job.py          # Job persistence model
│
├── workers/
│   └── scan_worker.py          # Background job processor
│
├── openeasd.py                 # API server entry point
└── pyproject.toml
```

## Quick Start

### Start API Server
```bash
# Install dependencies
uv sync

# Start API server
python openeasd.py

# Or with auto-reload for development
python openeasd.py --reload

# API docs available at
http://localhost:8000/docs
```

### Start Worker (separate terminal)
```bash
python -m workers.scan_worker
```

### Test API
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Create domain
curl -X POST http://localhost:8000/api/v1/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_primary": true}'

# Create scan (async)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Poll for status
curl http://localhost:8000/api/v1/scans/{scan_id}
```

## Data Flow

### Async Scan Flow (with Job Persistence)

```
Client                    API                  Database            Worker
  │                        │                      │                   │
  │──POST /scans─────────▶│                      │                   │
  │                        │──Create scan record─▶│                   │
  │                        │──Create job (pending)▶│                   │
  │                        │──PUSH to ZeroMQ─────▶│                   │
  │                        │──Mark job queued────▶│                   │
  │◀──202 {scan_id}───────│                      │                   │
  │                        │                      │                   │
  │                        │                      │◀──PULL job───────│
  │                        │                      │◀──Claim job──────│
  │                        │                      │                   │
  │──GET /scans/{id}─────▶│                      │       8-step workflow
  │◀──{status: running}───│                      │                   │
  │                        │                      │                   │
  │                        │                      │◀──Complete job───│
  │──GET /scans/{id}─────▶│                      │                   │
  │◀──{status: completed}─│                      │                   │
```

### Job Lifecycle States
```
pending -> queued -> processing -> completed/failed/cancelled
```

### 8-Step Scan Workflow
```
1. step1_discover_subdomains (subfinder)
2. step2_resolve_dns (dnsx)
3. step3_scan_ports (naabu)
4. step4_probe_http (httpx)
5. step5_verify_tls (tlsx)
6. step6_detect_services (nmap -sV)
7. step7_detect_vulnerabilities (nuclei + nmap NSE) - both mandatory for non-web ports
8. step8_analyze (risk scoring)
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| API | FastAPI 0.109+ |
| Validation | Pydantic v2 |
| Database | SQLite + SQLModel |
| Messaging | ZeroMQ (pyzmq) |
| Package Manager | uv |
| Testing | pytest |

## Key Dependencies

```toml
dependencies = [
    "fastapi>=0.109.0",
    "uvicorn[standard]>=0.27.0",
    "pydantic>=2.5.0",
    "sqlmodel>=0.0.14",
    "pyzmq>=25.0.0",
    "pyyaml==6.0.1",
]
```

## For AI Assistants

### Guidelines
- API is full-access (GET, POST, PUT, DELETE)
- No CLI layer - all operations via API
- Scans are async - use job queue
- Worker processes jobs from ZeroMQ
- Polling for scan status (no WebSocket)

### Adding Features

**New API Endpoint**:
1. Add schema in `src/api/schemas/`
2. Add service method in `src/orchestrator/`
3. Add route in `src/api/routes/`
4. Register in `src/api/main.py`

**New Security Tool**:
1. Create `src/tools/{tool}/`
2. Implement subprocess execution
3. Add step to `ScanWorkflowOrchestrator`

**New Detector**:
1. Extend `BaseDetector` in `src/analysis/detectors/`
2. Register in `AnalysisService._load_detectors()`

## Test Suite

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=src
```

**Current Status**: 312 tests passing (6 dead tests removed Dec 3, 2025)

---

**Last Updated**: December 4, 2025
**Architecture Version**: 6-Layer API-Only with ZeroMQ + Job Persistence
**Interface**: API only (no CLI)
**Key Components**: ScanWorkflowOrchestrator, Job model, Worker with stale recovery
