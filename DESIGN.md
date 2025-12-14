# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (6-Layer API-Only Design)
**Version**: 10.0 - API-Only with ZeroMQ Messaging
**Last Updated**: December 2025
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Architecture Overview

OpenEASD implements automated external attack surface detection through a streamlined 6-layer API-only architecture with ZeroMQ-based async job processing.

### System Architecture (6-Layer API-Only Design)

```
┌─────────────────────────────────────────────────────────────┐
│              OpenEASD - 6-Layer Architecture                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: API Layer (Full CRUD REST API) ✅                 │
│    • FastAPI REST endpoints (GET, POST, PUT, DELETE)       │
│    • Pydantic v2 validation                                │
│    • CORS middleware                                       │
│    • Async scan creation via job queue                     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Service Layer (Business Logic) ✅                 │
│    • DomainService, ScanService, FindingsService           │
│    • AnalysisService                                       │
│    • Shared business logic                                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Messaging Layer (ZeroMQ Job Queue) ✅             │
│    • PUSH/PULL pattern for job distribution                │
│    • Async scan job processing                             │
│    • Worker process coordination                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Tools Layer (Security Tools) ✅                   │
│    • Subfinder - Passive subdomain discovery               │
│    • Naabu - Fast port scanning                            │
│    • Dnsx - DNS resolution                                 │
│    • Httpx - HTTP probing                                  │
│    • Tlsx - TLS verification                               │
│    • Nmap - Service detection + NSE scripts                │
│    • Nuclei - Network vulnerability scanning               │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Analysis Layer (Vulnerability Detection) ✅       │
│    • RiskScorer (0-100 deterministic scoring)              │
│    • PortVulnerabilityDetector                             │
│    • ServiceDetector                                       │
│    • Finding deduplication and CVE mapping                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Database Layer (Storage) ✅                       │
│    • SQLite with SQLModel ORM                              │
│    • 15+ tables for domains, scans, findings               │
│    • Timezone-aware timestamps (IST)                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Background Worker Process                                  │
│    • Pulls jobs from ZeroMQ queue                          │
│    • Executes scan workflows                               │
│    • Updates scan status in database                       │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Status

| Layer | Status | Components | Notes |
|-------|--------|------------|-------|
| **Layer 1: API** | Complete | FastAPI, Pydantic v2 | Full CRUD endpoints |
| **Layer 2: Service** | Complete | ScanService, ScanWorkflowOrchestrator | 8-step workflow |
| **Layer 3: Messaging** | Complete | ZeroMQ + Job persistence | Database-backed queue |
| **Layer 4: Tools** | Complete | 7 security tools | Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei |
| **Layer 5: Analysis** | Complete | RiskScorer, Detectors | 95% test coverage |
| **Layer 6: Database** | Complete | SQLite + SQLModel + Job model | 15+ tables |

---

## API-Only Design

### Why API-Only?

**Simplified Architecture**:
- Single entry point for all operations
- No CLI layer to maintain
- Clean separation via REST endpoints
- Easy integration with external systems

**Async Processing**:
- Scans run asynchronously via worker process
- Immediate API response (HTTP 202 Accepted)
- Poll for status updates
- Database-backed job persistence

---

## Layer Details

### Layer 1: API Layer

**Purpose**: Full CRUD REST API for all operations
**Technology**: FastAPI 0.109+, Pydantic v2, Uvicorn

**Endpoints**:
```
# Health
GET  /api/v1/health                     # Health check

# Domains (Full CRUD)
GET  /api/v1/domains                    # List domains
POST /api/v1/domains                    # Create domain
GET  /api/v1/domains/{domain}           # Domain details
PUT  /api/v1/domains/{domain}           # Update domain
DELETE /api/v1/domains/{domain}         # Delete domain

# Scans (Async)
GET  /api/v1/scans                      # List scans
POST /api/v1/scans                      # Create scan (async, returns 202)
GET  /api/v1/scans/{scan_id}            # Scan status (poll this)
GET  /api/v1/scans/{scan_id}/results    # Scan results

# Findings
GET  /api/v1/findings                   # List findings
GET  /api/v1/findings/{id}              # Finding details
GET  /api/v1/findings/statistics/summary # Statistics
```

### Layer 2: Service Layer

**Purpose**: Shared business logic for API and worker
**Services**:
- **DomainService**: Domain CRUD operations
- **ScanService**: Scan CRUD operations and status management
- **ScanWorkflowOrchestrator**: 8-step scan workflow execution
- **AnalysisService**: Vulnerability detection orchestration
- **FindingsService**: Finding retrieval and statistics

**ScanWorkflowOrchestrator** (NEW):
Handles the complete scan workflow with 8 discrete steps:
1. `step1_discover_subdomains` - Subfinder for subdomain enumeration
2. `step2_resolve_dns` - Dnsx for DNS resolution and IP filtering
3. `step3_scan_ports` - Naabu for port scanning
4. `step4_probe_http` - Httpx for web service detection
5. `step5_verify_tls` - Tlsx for TLS verification on non-web ports
6. `step6_detect_services` - Nmap for service identification
7. `step7_detect_vulnerabilities` - Nmap for vulnerability scanning
8. `step8_analyze` - Risk scoring and finding generation

### Layer 3: Messaging Layer

**Purpose**: Async job distribution between API and workers with database persistence
**Technology**: ZeroMQ (pyzmq) + SQLite job persistence

**Components**:
- **JobQueue**: PUSH/PULL socket management with DB integration
- **MessagingConfig**: Connection settings
- **Job Model**: Database-persisted job records (NEW)

**Job Model** (NEW - `src/data/models/job.py`):
Jobs are persisted to SQLite BEFORE being pushed to ZeroMQ, ensuring no jobs are lost if workers crash.

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | Primary key (UUID) |
| `job_type` | str | Job type ("scan", "analysis") |
| `payload` | JSON | Job payload data |
| `status` | str | pending/queued/processing/completed/failed/cancelled |
| `scan_id` | str | Associated scan session ID |
| `worker_id` | str | Worker that claimed the job |
| `created_at` | datetime | Job creation time |
| `queued_at` | datetime | When pushed to ZeroMQ |
| `started_at` | datetime | When worker started processing |
| `completed_at` | datetime | When job finished |
| `error_message` | str | Error details if failed |
| `retry_count` | int | Number of retry attempts |
| `max_retries` | int | Maximum retry limit (default: 3) |
| `priority` | int | Job priority (lower = higher priority) |

**Job Lifecycle**:
```
pending -> queued -> processing -> completed
                  ↘            ↗
                    failed/cancelled
```

**Job CRUD Methods** (SQLModelManager):
- `create_job()` - Create new job record
- `mark_job_queued()` - Update status when pushed to ZeroMQ
- `claim_job()` - Worker claims job for processing
- `complete_job()` - Mark job as completed/failed
- `get_job()` - Retrieve job by ID
- `get_stale_jobs()` - Find jobs stuck in processing (>30 min)
- `get_pending_jobs()` - List jobs waiting for workers
- `retry_job()` - Reset job for retry
- `cancel_job()` - Cancel a pending/queued job
- `get_job_statistics()` - Get counts by status
- `cleanup_old_jobs()` - Remove old completed jobs

**Pattern with Job Persistence**:
```
API Server                    Database                    Worker
     │                            │                          │
     │ POST /scans               │                          │
     │ ─────────────────────────>│ Create job (pending)     │
     │                            │                          │
     │ PUSH to ZeroMQ            │                          │
     │ ─────────────────────────>│ Mark job queued          │
     │                            │                          │
     │ Return 202                 │                          │
     │                            │<─────────────────────────│ PULL job
     │                            │<─────────────────────────│ Claim job
     │                            │                          │
     │                            │                      8-step workflow
     │                            │                          │
     │                            │<─────────────────────────│ Complete job
     ▼                            ▼                          ▼
```

### Layer 4: Analysis Layer

**Purpose**: Automated vulnerability detection and risk scoring
**Components**:
- **RiskScorer**: Deterministic scoring (0-100)
  - Base score (0-40): Inherent risk
  - Context score (0-40): Business context
  - Exposure score (0-20): Public accessibility
- **PortVulnerabilityDetector**: Port-based vulnerability detection
- **BaseDetector**: Abstract pattern for extensibility

### Layer 5: Tools Layer

**Purpose**: Security tool execution via subprocess
**Tools**:
- **Subfinder**: Passive subdomain discovery
- **Naabu**: Fast port scanning
- **Dnsx**: DNS resolution
- **Httpx**: HTTP probing
- **Nmap**: Service detection and vulnerability scanning

### Layer 6: Database Layer

**Purpose**: Data persistence with SQLModel ORM
**Technology**: SQLite, SQLModel, Python 3.11+

**Core Tables**:
- domains, scan_sessions, subdomain_history
- security_alerts, findings, vulnerabilities
- cve_mappings, finding_groups

---

## Async Scan Flow

```
1. Client: POST /api/v1/scans {"domain": "example.com"}
    ↓
2. API Layer:
    - Validate request (Pydantic)
    - Create scan record (status: pending)
    - Create job record (status: pending) <- NEW: Job persistence
    - Push job to ZeroMQ queue
    - Mark job as queued <- NEW: Track queue state
    - Return 202 Accepted with scan_id
    ↓
3. Client polls: GET /api/v1/scans/{scan_id}
    ↓
4. Worker Process (background):
    - Pull job from ZeroMQ
    - Claim job in database (tracks worker_id) <- NEW: Job claiming
    - Update scan status to "running"
    - Execute 8-step workflow via ScanWorkflowOrchestrator:
      1. Subfinder (subdomain discovery)
      2. Dnsx (DNS resolution)
      3. Naabu (port scanning)
      4. Httpx (HTTP probing)
      5. Tlsx (TLS verification)
      6. Nmap (service detection)
      7. Nmap (vulnerability detection)
      8. Analysis (risk scoring)
    - Save results to database
    - Update scan status to "completed"
    - Mark job as completed <- NEW: Job completion tracking
    ↓
5. Client: GET /api/v1/scans/{scan_id}/results
    - Returns full scan results
```

## Stale Job Recovery

Workers periodically check for stale jobs (processing > 30 minutes):

```
1. Worker checks every 60 seconds for stale jobs
2. If found, worker marks associated scan as "failed"
3. Job is either:
   - Reset for retry (if retry_count < max_retries)
   - Marked as permanently failed (if max retries exceeded)
4. Recovered jobs can be picked up by any worker
```

---

## Project Structure

```
OpenEASD/
├── src/
│   ├── api/                  # Layer 1: API
│   │   ├── main.py           # FastAPI application
│   │   ├── dependencies.py   # Dependency injection
│   │   ├── routes/
│   │   │   ├── domains.py    # Domain CRUD
│   │   │   ├── scans.py      # Scan operations
│   │   │   ├── findings.py   # Findings retrieval
│   │   │   └── health.py     # Health check
│   │   └── schemas/
│   │       ├── domain.py
│   │       ├── scan.py
│   │       └── finding.py
│   ├── services/             # Layer 2: Services
│   │   ├── domain_service.py
│   │   ├── scan_service.py              # CRUD operations
│   │   ├── scan_workflow_orchestrator.py # 8-step workflow
│   │   └── findings_service.py
│   ├── messaging/            # Layer 3: Messaging
│   │   ├── __init__.py
│   │   ├── config.py         # ZeroMQ configuration
│   │   └── job_queue.py      # PUSH/PULL job queue
│   ├── analysis/             # Layer 4: Analysis
│   │   ├── scoring/
│   │   │   └── risk_scorer.py
│   │   └── detectors/
│   │       └── port_detector.py
│   ├── tools/                # Layer 5: Tools
│   │   ├── subfinder/
│   │   ├── naabu/
│   │   ├── dnsx/
│   │   ├── httpx/
│   │   └── nmap/
│   └── data/                 # Layer 6: Database
│       ├── database/
│       │   └── sqlmodel_manager.py  # 10+ job CRUD methods
│       └── models/
│           └── job.py               # Job persistence model
├── workers/                  # Background Workers
│   ├── __init__.py
│   └── scan_worker.py        # Scan job processor
├── tests/                    # Test suite
├── openeasd.py              # API server entry point
└── pyproject.toml           # Dependencies (uv)
```

---

## Technology Stack

- **API**: FastAPI 0.109+, Pydantic v2, Uvicorn
- **Messaging**: ZeroMQ (pyzmq 25.0+)
- **Database**: SQLite, SQLModel
- **Analysis**: Custom risk scoring engine
- **Tools**:
  - Subfinder (subdomain discovery)
  - Naabu (port scanning)
  - Dnsx (DNS resolution)
  - Httpx (HTTP probing)
  - Nmap (service detection + vulnerability scanning)
- **Testing**: pytest (318 tests, 79%+ coverage)
- **Package Manager**: uv

---

## Quick Start

### Option 1: Single Command (Development)
```bash
# Install dependencies
uv sync

# Start both API server and worker
python run_dev.py

# With custom port and multiple workers
python run_dev.py --port 8080 --workers 3
```

### Option 2: Separate Processes (Production)
```bash
# Terminal 1: Start API server
python openeasd.py --port 8000

# Terminal 2: Start worker
python -m workers.scan_worker
```

### API Usage
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Create a domain
curl -X POST http://localhost:8000/api/v1/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_primary": true}'

# Start a scan (async)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Poll scan status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Get results when completed
curl http://localhost:8000/api/v1/scans/{scan_id}/results
```

---

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

ZeroMQ will automatically distribute jobs across workers.

---

**Architecture Status**: 6-Layer API-Only (All Complete)
**Key Changes**:
- Job persistence (database-backed queue, stale recovery)
- ScanWorkflowOrchestrator (8-step workflow extracted from ScanService)
- Worker ID tracking and graceful shutdown
**Test Coverage**: 79%+ (318 tests passing)
**Last Updated**: December 4, 2025
