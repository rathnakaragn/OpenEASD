# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (6-Layer API-Only Design)
**Version**: 11.0 - API-Only with Database Job Queue
**Last Updated**: January 2026
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Architecture Overview

OpenEASD implements automated external attack surface detection through a streamlined 6-layer API-only architecture with database-backed async job processing.

### System Architecture (6-Layer API-Only Design)

```
+-------------------------------------------------------------+
|              OpenEASD - 6-Layer Architecture                 |
+-------------------------------------------------------------+
|  Layer 1: API Layer (Full CRUD REST API)                    |
|    - FastAPI REST endpoints (GET, POST, PUT, DELETE)        |
|    - Pydantic v2 validation                                 |
|    - CORS middleware                                        |
|    - Web dashboard served from /                            |
+-------------------------------------------------------------+
|  Layer 2: Orchestrator Layer (Business Logic)               |
|    - DomainService, ScanService, FindingsService            |
|    - JobService, HealthService                              |
|    - ScanWorkflowOrchestrator (8-step workflow)            |
+-------------------------------------------------------------+
|  Layer 3: Database Job Queue                                |
|    - Jobs stored in SQLite database                         |
|    - Worker polls database for pending jobs                 |
|    - Atomic job claiming with worker ID tracking            |
|    - Stale job recovery (30-min timeout)                    |
+-------------------------------------------------------------+
|  Layer 4: Tools Layer (Security Tools)                      |
|    - Subfinder - Passive subdomain discovery                |
|    - Naabu - Fast port scanning                             |
|    - Dnsx - DNS resolution                                  |
|    - Httpx - HTTP probing                                   |
|    - Tlsx - TLS verification                                |
|    - Nmap - Service detection + NSE scripts                 |
|    - Nuclei - Network vulnerability scanning                |
+-------------------------------------------------------------+
|  Layer 5: Analysis Layer (Vulnerability Detection)          |
|    - RiskScorer (0-100 deterministic scoring)              |
|    - PortVulnerabilityDetector                             |
|    - ServiceDetector                                        |
|    - Finding deduplication and CVE mapping                 |
+-------------------------------------------------------------+
|  Layer 6: Database Layer (Storage)                          |
|    - SQLite with SQLModel ORM                              |
|    - 15+ tables for domains, scans, findings, jobs         |
|    - Timezone-aware timestamps (IST)                        |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
|  Background Worker Process                                   |
|    - Polls database for pending jobs                        |
|    - Executes scan workflows                                |
|    - Updates scan status in database                        |
|    - Stale job recovery on startup                          |
|    - Run: python -m workers.scan_worker                     |
+-------------------------------------------------------------+
```

## Implementation Status

| Layer | Status | Components | Notes |
|-------|--------|------------|-------|
| **Layer 1: API** | Complete | FastAPI, Pydantic v2 | Full CRUD endpoints |
| **Layer 2: Orchestrator** | Complete | ScanService, ScanWorkflowOrchestrator | 8-step workflow |
| **Layer 3: Job Queue** | Complete | Job model, DB polling | Database-backed queue |
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
DELETE /api/v1/scans/{scan_id}          # Delete scan
POST /api/v1/scans/{scan_id}/cancel     # Cancel scan
POST /api/v1/scans/{scan_id}/retry      # Retry failed scan

# Findings
GET  /api/v1/findings                   # List findings
GET  /api/v1/findings/{id}              # Finding details
PUT  /api/v1/findings/{id}              # Update finding status
GET  /api/v1/findings/stats             # Statistics

# Jobs
GET  /api/v1/jobs                       # List jobs
GET  /api/v1/jobs/{id}                  # Job status
GET  /api/v1/jobs/stats                 # Job statistics
```

### Layer 2: Orchestrator Layer

**Purpose**: Shared business logic for API and workers
**Services**:
- **DomainService**: Domain CRUD operations
- **ScanService**: Scan CRUD operations and status management
- **ScanWorkflowOrchestrator**: 8-step scan workflow execution
- **FindingsService**: Finding retrieval and statistics
- **JobService**: Job queue management
- **HealthService**: Health check operations

**ScanWorkflowOrchestrator**:
Handles the complete scan workflow with 8 discrete steps:
1. `step1_discover_subdomains` - Subfinder for subdomain enumeration
2. `step2_resolve_dns` - Dnsx for DNS resolution and IP filtering
3. `step3_scan_ports` - Naabu for port scanning
4. `step4_probe_http` - Httpx for web service detection
5. `step5_verify_tls` - Tlsx for TLS verification on non-web ports
6. `step6_detect_services` - Nmap for service identification
7. `step7_detect_vulnerabilities` - Nmap for vulnerability scanning
8. `step8_analyze` - Risk scoring and finding generation

### Layer 3: Database Job Queue

**Purpose**: Async job distribution via database polling
**Technology**: SQLite job table, polling mechanism

**Job Model** (`src/data/models/job.py`):
Jobs are persisted to SQLite and processed by workers via database polling.

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | Primary key (UUID) |
| `job_type` | str | Job type ("scan", "analysis") |
| `payload` | JSON | Job payload data |
| `status` | str | pending/processing/completed/failed/cancelled |
| `scan_id` | str | Associated scan session ID |
| `worker_id` | str | Worker that claimed the job |
| `created_at` | datetime | Job creation time |
| `started_at` | datetime | When worker started processing |
| `completed_at` | datetime | When job finished |
| `error_message` | str | Error details if failed |
| `retry_count` | int | Number of retry attempts |
| `max_retries` | int | Maximum retry limit (default: 3) |

**Job Lifecycle**:
```
pending -> processing -> completed
              |
              +-> failed/cancelled
```

**Worker Behavior**:
- Polls database every 2 seconds for pending jobs
- Claims job atomically with worker ID
- Executes 8-step scan workflow
- Marks job completed/failed
- Recovers stale jobs (processing > 30 min)

### Layer 4: Tools Layer

**Purpose**: Security tool execution via subprocess
**Tools**:
- **Subfinder**: Passive subdomain discovery
- **Naabu**: Fast port scanning
- **Dnsx**: DNS resolution
- **Httpx**: HTTP probing
- **Tlsx**: TLS/SSL verification
- **Nmap**: Service detection and vulnerability scanning
- **Nuclei**: Network vulnerability scanning

### Layer 5: Analysis Layer

**Purpose**: Automated vulnerability detection and risk scoring
**Components**:
- **RiskScorer**: Deterministic scoring (0-100)
  - Base score (0-40): Inherent risk
  - Context score (0-40): Business context
  - Exposure score (0-20): Public accessibility
- **PortVulnerabilityDetector**: Port-based vulnerability detection
- **ServiceDetector**: Service identification risks
- **BaseDetector**: Abstract pattern for extensibility

### Layer 6: Database Layer

**Purpose**: Data persistence with SQLModel ORM
**Technology**: SQLite, SQLModel, Python 3.11+

**Core Tables**:
- domains, scan_sessions, subdomain_history
- security_alerts, findings, vulnerabilities
- cve_mappings, finding_groups, jobs

---

## Async Scan Flow

```
1. Client: POST /api/v1/scans {"domain": "example.com"}
    |
2. API Layer:
    - Validate request (Pydantic)
    - Create scan record (status: pending)
    - Create job record (status: pending)
    - Return 202 Accepted with scan_id
    |
3. Client polls: GET /api/v1/scans/{scan_id}
    |
4. Worker Process (background):
    - Poll database for pending jobs
    - Claim job atomically (tracks worker_id)
    - Update scan status to "running"
    - Execute 8-step workflow via ScanWorkflowOrchestrator:
      1. Subfinder (subdomain discovery)
      2. Dnsx (DNS resolution)
      3. Naabu (port scanning)
      4. Httpx (HTTP probing)
      5. Tlsx (TLS verification)
      6. Nmap (service detection)
      7. Nmap/Nuclei (vulnerability detection)
      8. Analysis (risk scoring)
    - Save results to database
    - Update scan status to "completed"
    - Mark job as completed
    |
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
│   │   │   ├── jobs.py       # Job queue endpoints
│   │   │   └── health.py     # Health check
│   │   └── schemas/
│   │       ├── domain.py
│   │       ├── scan.py
│   │       └── finding.py
│   ├── orchestrator/         # Layer 2: Orchestrator
│   │   ├── domain_service.py
│   │   ├── scan_service.py              # CRUD operations
│   │   ├── scan_workflow_orchestrator.py # 8-step workflow
│   │   ├── findings_service.py
│   │   ├── job_service.py
│   │   └── health_service.py
│   ├── analysis/             # Layer 5: Analysis
│   │   ├── analysis_service.py
│   │   ├── scoring/
│   │   │   └── risk_scorer.py
│   │   └── detectors/
│   │       ├── port_detector.py
│   │       └── service_detector.py
│   ├── tools/                # Layer 4: Tools
│   │   ├── subfinder/
│   │   ├── naabu/
│   │   ├── dnsx/
│   │   ├── httpx/
│   │   ├── tlsx/
│   │   ├── nmap/
│   │   └── nuclei/
│   ├── data/                 # Layer 6: Database
│   │   ├── database/
│   │   │   └── sqlmodel_manager.py
│   │   └── models/
│   │       └── job.py               # Job persistence model
│   ├── frontend/             # Web Dashboard
│   │   ├── static/
│   │   └── templates/
│   ├── mcp/                  # MCP Server
│   │   └── server.py
│   └── utils/                # Utilities
├── workers/                  # Background Workers
│   └── scan_worker.py        # Scan job processor
├── tests/                    # Test suite
├── openeasd.py               # API server entry point
└── pyproject.toml            # Dependencies (uv)
```

---

## Technology Stack

- **API**: FastAPI 0.109+, Pydantic v2, Uvicorn
- **Database**: SQLite, SQLModel
- **Job Queue**: Database polling (no external dependencies)
- **Analysis**: Custom risk scoring engine
- **Tools**:
  - Subfinder (subdomain discovery)
  - Naabu (port scanning)
  - Dnsx (DNS resolution)
  - Httpx (HTTP probing)
  - Tlsx (TLS verification)
  - Nmap (service detection + vulnerability scanning)
  - Nuclei (vulnerability scanning)
- **Testing**: pytest
- **Package Manager**: uv
- **MCP**: fastmcp (Claude Code integration)

---

## Quick Start

### Running the Application
```bash
# Install dependencies
uv sync

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

Jobs are distributed across workers via atomic database claiming.

---

**Architecture Status**: 6-Layer API-Only (All Complete)
**Key Features**:
- Database-backed job queue (no external dependencies)
- ScanWorkflowOrchestrator (8-step workflow)
- Worker ID tracking and graceful shutdown
- Stale job recovery
- Web dashboard
- MCP server for Claude Code integration
**Last Updated**: January 29, 2026
