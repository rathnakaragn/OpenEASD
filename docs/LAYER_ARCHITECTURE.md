# OpenEASD Layer Architecture Guide

**Version**: 3.0
**Last Updated**: January 29, 2026
**Status**: Production-Ready (6-Layer API-Only Architecture)

> **New in v3.0**: Replaced ZeroMQ messaging with database job queue. Worker now polls database for jobs. Added web dashboard and MCP server.
>
> **New in v2.0**: Removed CLI Layer, API now supports full CRUD operations.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Layer 1: API Layer](#2-layer-1-api-layer-full-crud-rest)
3. [Layer 2: Orchestrator Layer](#3-layer-2-orchestrator-layer-business-logic)
4. [Layer 3: Database Job Queue](#4-layer-3-database-job-queue)
5. [Layer 4: Tools Layer](#5-layer-4-tools-layer-security-tools)
6. [Layer 5: Analysis Layer](#6-layer-5-analysis-layer-vulnerability-detection)
7. [Layer 6: Database Layer](#7-layer-6-database-layer-persistence)
8. [Data Flow Patterns](#8-data-flow-patterns)
9. [Background Workers](#9-background-workers)
10. [File Reference](#10-file-reference-by-layer)
11. [Best Practices](#11-best-practices)

---

## 1. Architecture Overview

### 1.1 Six-Layer Stack

OpenEASD implements a **6-layer API-only architecture** with clear separation of concerns:

```
+-------------------------------------------------------------+
| Layer 1: API Layer (FastAPI)                                 |
| Purpose: Full CRUD REST API for all operations               |
| Access: Remote (HTTP), GET/POST/PUT/DELETE                   |
| Port: 8000                                                   |
+-------------------------------------------------------------+
| Layer 2: Orchestrator Layer                                  |
| Purpose: Shared business logic for API and workers           |
| Access: Internal (Python imports)                            |
| Components: ScanService, ScanWorkflowOrchestrator (8-step)   |
+-------------------------------------------------------------+
| Layer 3: Database Job Queue                                  |
| Purpose: Async job distribution via database polling         |
| Access: SQLite database                                      |
| Components: Job model, worker polling, stale recovery        |
+-------------------------------------------------------------+
| Layer 4: Tools Layer                                         |
| Purpose: Execute external security tools                     |
| Access: Subprocess execution                                 |
| Tools: Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei    |
+-------------------------------------------------------------+
| Layer 5: Analysis Layer                                      |
| Purpose: Automated vulnerability detection and risk scoring  |
| Access: Internal (called by Orchestrator Layer)              |
| Components: RiskScorer, Detectors, Finding models            |
+-------------------------------------------------------------+
| Layer 6: Database Layer (SQLite + SQLModel)                  |
| Purpose: Persistent data storage                             |
| Access: Internal (SQLModel ORM)                              |
| Storage: data/openeasd.db                                    |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| Background Workers (workers/scan_worker.py)                  |
| Purpose: Process scan jobs from database queue               |
| Access: Polls database, writes results                       |
| Features: Stale recovery, worker ID tracking                 |
| Run: python -m workers.scan_worker                           |
+-------------------------------------------------------------+
```

### 1.2 Design Principles

1. **Separation of Concerns**: Each layer has specific, well-defined responsibilities
2. **API-First Design**: All operations through REST API, no CLI
3. **Async Processing**: Scans run asynchronously via database job queue
4. **Loose Coupling**: Layers communicate through well-defined interfaces
5. **Dependency Injection**: Services injected at runtime
6. **Single Responsibility**: Each component does one thing well
7. **Extensibility**: Easy to add new detectors, tools, or endpoints
8. **No External Dependencies for Job Queue**: Database-backed, no ZeroMQ required

### 1.3 Technology Stack

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| API | FastAPI | 0.109+ | Async web framework |
| API | Pydantic | 2.5+ | Data validation |
| API | Uvicorn | 0.27+ | ASGI server |
| Orchestrator | Python | 3.11+ | Business logic |
| Job Queue | SQLite | 3.x | Job persistence |
| Analysis | Python | 3.11+ | Vulnerability detection |
| Tools | Subprocess | stdlib | Tool execution |
| Database | SQLModel | - | ORM layer |
| Database | SQLite | 3.x | Embedded database |

### 1.4 Current Status

- **Implementation**: 100% complete (all 6 layers)
- **API Endpoints**: 15+ endpoints (full CRUD)
- **Background Workers**: 1 (scan_worker.py with DB polling)
- **Database Tables**: 15+ tables
- **Security Tools**: 7 integrated (Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei)

---

## 2. Layer 1: API Layer (Full CRUD REST)

### 2.1 Purpose

Provide **complete REST API access** for all domain management, scan operations, and findings retrieval. All operations are performed through the API - there is no CLI.

**Key Characteristics**:
- Full CRUD operations (GET, POST, PUT, DELETE)
- Async scan creation (returns 202 Accepted)
- FastAPI with automatic OpenAPI documentation
- CORS middleware for web integrations
- Pydantic v2 validation
- Web dashboard served from root path

### 2.2 Responsibilities

- **HTTP Request Handling**: Parse and validate incoming HTTP requests
- **Request Validation**: Pydantic v2 schema validation
- **CORS Configuration**: Cross-origin request handling
- **API Documentation**: Auto-generated OpenAPI/Swagger docs
- **Response Formatting**: JSON serialization with proper status codes
- **Error Handling**: HTTP exception handling with proper codes
- **Job Creation**: Create jobs in database for async processing
- **Web Dashboard**: Serve static files and templates

### 2.3 API Endpoints

```
Health
  GET  /api/v1/health                     # Health check

Domains (Full CRUD)
  GET  /api/v1/domains                    # List domains
  POST /api/v1/domains                    # Create domain
  GET  /api/v1/domains/{domain}           # Domain details
  PUT  /api/v1/domains/{domain}           # Update domain
  DELETE /api/v1/domains/{domain}         # Delete domain

Scans (Async)
  GET  /api/v1/scans                      # List scans
  POST /api/v1/scans                      # Create scan (async, returns 202)
  GET  /api/v1/scans/{scan_id}            # Scan status (poll this)
  GET  /api/v1/scans/{scan_id}/results    # Scan results
  DELETE /api/v1/scans/{scan_id}          # Delete scan
  POST /api/v1/scans/{scan_id}/cancel     # Cancel scan
  POST /api/v1/scans/{scan_id}/retry      # Retry failed scan

Findings
  GET  /api/v1/findings                   # List findings
  GET  /api/v1/findings/{id}              # Finding details
  PUT  /api/v1/findings/{id}              # Update finding status
  GET  /api/v1/findings/stats             # Statistics

Jobs
  GET  /api/v1/jobs                       # List jobs
  GET  /api/v1/jobs/{id}                  # Job status
  GET  /api/v1/jobs/stats                 # Job statistics
```

### 2.4 Files

| File | Purpose |
|------|---------|
| `src/api/main.py` | FastAPI app initialization |
| `src/api/dependencies.py` | Dependency injection |
| `src/api/routes/health.py` | Health check endpoint |
| `src/api/routes/domains.py` | Domain endpoints |
| `src/api/routes/scans.py` | Scan endpoints |
| `src/api/routes/findings.py` | Findings endpoints |
| `src/api/routes/jobs.py` | Job queue endpoints |
| `src/api/schemas/*.py` | Pydantic schemas |

---

## 3. Layer 2: Orchestrator Layer (Business Logic)

### 3.1 Purpose

Provide **shared business logic** for the API layer. The orchestrator layer coordinates between multiple components and enforces business rules.

**Key Characteristics**:
- Domain logic and validation
- Orchestrates complex workflows via ScanWorkflowOrchestrator
- Handles errors and logging
- Dependency injection ready
- Clear separation: ScanService (CRUD) vs ScanWorkflowOrchestrator (execution)

### 3.2 Services

#### DomainService
- `create_domain()` - Add new domain with validation
- `list_domains()` - Get domains with filtering
- `get_domain()` - Get domain details
- `update_domain()` - Modify domain properties
- `delete_domain()` - Remove domain

#### ScanService (CRUD Operations)
- `create_scan()` - Create new scan session
- `get_scan_status()` - Get current scan progress
- `get_scan_results()` - Retrieve scan outputs
- `list_scans()` - Get paginated scan history
- `update_scan_status()` - Update scan status
- `create_and_queue_scan()` - Create scan and job in database
- `execute_scan_workflow()` - Delegate to ScanWorkflowOrchestrator

#### ScanWorkflowOrchestrator (Workflow Execution)
The 8-step scan workflow:
- `step1_discover_subdomains()` - Subfinder for subdomain enumeration
- `step2_resolve_dns()` - Dnsx for DNS resolution
- `step3_scan_ports()` - Naabu for port scanning
- `step4_probe_http()` - Httpx for web service detection
- `step5_verify_tls()` - Tlsx for TLS verification
- `step6_detect_services()` - Nmap for service identification
- `step7_detect_vulnerabilities()` - Nmap/Nuclei for vulnerability scanning
- `step8_analyze()` - Risk scoring and finding generation
- `execute_workflow()` - Run complete 8-step workflow

#### FindingsService
- `list_findings()` - Get findings with filtering
- `get_finding()` - Retrieve specific finding
- `update_finding_status()` - Change finding status
- `get_statistics()` - Calculate finding statistics

#### JobService
- `list_jobs()` - Get jobs with filtering
- `get_job()` - Get job details
- `get_statistics()` - Job queue statistics

### 3.3 Files

| File | Purpose |
|------|---------|
| `src/orchestrator/domain_service.py` | Domain business logic |
| `src/orchestrator/scan_service.py` | Scan CRUD operations |
| `src/orchestrator/scan_workflow_orchestrator.py` | 8-step workflow |
| `src/orchestrator/findings_service.py` | Finding management |
| `src/orchestrator/job_service.py` | Job queue management |
| `src/orchestrator/health_service.py` | Health check logic |
| `src/orchestrator/exceptions.py` | Custom exceptions |

---

## 4. Layer 3: Database Job Queue

### 4.1 Purpose

Provide **async job distribution** via database polling. Jobs are stored in SQLite and workers poll for pending jobs, providing a simple, dependency-free job queue.

**Key Characteristics**:
- No external dependencies (no ZeroMQ, Redis, etc.)
- Jobs persisted to SQLite database
- Workers poll database for pending jobs
- Atomic job claiming with worker ID
- Stale job recovery (jobs stuck > 30 minutes)
- Multiple workers supported

### 4.2 Job Model

Jobs are stored in the `jobs` table:

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

### 4.3 Job Lifecycle

```
pending -> processing -> completed
              |
              +-> failed/cancelled
```

### 4.4 Database Methods (SQLModelManager)

- `create_job()` - Create new job record
- `claim_next_job()` - Atomically claim pending job
- `complete_job()` - Mark job as completed/failed
- `get_job()` - Retrieve job by ID
- `get_stale_jobs()` - Find jobs stuck in processing (>30 min)
- `get_pending_jobs()` - List jobs waiting for workers
- `retry_job()` - Reset job for retry
- `cancel_job()` - Cancel a pending job
- `get_job_statistics()` - Get counts by status
- `cleanup_old_jobs()` - Remove old completed jobs

### 4.5 Architecture Pattern

```
+---------------+         +---------------+         +---------------+
|   API Server  |         |   Database    |         |    Workers    |
|               |         |               |         |               |
|  POST /scans  |  INSERT |    jobs       |  POLL   | scan_worker   |
|  -----------> | ------> |    table      | <------ |               |
|               |         |               |         |  Process Jobs |
|  Returns 202  |         |               |         |  Update DB    |
+---------------+         +---------------+         +---------------+
        |                        ^                          |
        |                        |                          |
        +------------------------+--------------------------+
                           Status Updates
```

### 4.6 Worker Polling Configuration

```python
POLL_INTERVAL_SECONDS = 2      # Check for jobs every 2 seconds
STALE_JOB_THRESHOLD_MINUTES = 30  # Jobs stuck > 30 min are stale
RECOVERY_CHECK_INTERVAL = 60   # Check for stale jobs every 60 seconds
```

### 4.7 Files

| File | Purpose |
|------|---------|
| `src/data/models/job.py` | Job persistence model |
| `src/data/database/sqlmodel_manager.py` | Job CRUD methods |
| `workers/scan_worker.py` | Scan job processor |

---

## 5. Layer 4: Tools Layer (Security Tools)

### 5.1 Purpose

Execute external security tools via subprocess and parse their JSON output.

**Tools**:
- **Subfinder**: Passive subdomain discovery
- **Naabu**: Fast port scanning
- **Dnsx**: DNS resolution
- **Httpx**: HTTP probing
- **Tlsx**: TLS/SSL verification
- **Nmap**: Service detection and vulnerability scanning
- **Nuclei**: Network vulnerability scanning

### 5.2 Files

| Directory | Purpose |
|-----------|---------|
| `src/tools/subfinder/` | Subdomain discovery |
| `src/tools/naabu/` | Port scanning |
| `src/tools/dnsx/` | DNS resolution |
| `src/tools/httpx/` | HTTP probing |
| `src/tools/tlsx/` | TLS verification |
| `src/tools/nmap/` | Service detection |
| `src/tools/nuclei/` | Vulnerability scanning |

---

## 6. Layer 5: Analysis Layer (Vulnerability Detection)

### 6.1 Purpose

Provide **automated vulnerability detection and risk scoring** for scan results.

**Key Characteristics**:
- Deterministic risk scoring (0-100)
- Multiple detectors (extensible pattern)
- Finding deduplication
- CVE enrichment capability

### 6.2 Components

- **RiskScorer**: Calculate 0-100 risk scores
  - Base score (0-40): Inherent risk
  - Context score (0-40): Business context
  - Exposure score (0-20): Public accessibility
- **PortVulnerabilityDetector**: Port-based vulnerability detection
- **ServiceDetector**: Service identification risks
- **BaseDetector**: Abstract pattern for extensibility

### 6.3 Files

| File | Purpose |
|------|---------|
| `src/analysis/analysis_service.py` | Analysis orchestration |
| `src/analysis/scoring/risk_scorer.py` | Risk scoring |
| `src/analysis/detectors/port_detector.py` | Port vulnerabilities |
| `src/analysis/detectors/service_detector.py` | Service vulnerabilities |

---

## 7. Layer 6: Database Layer (Persistence)

### 7.1 Purpose

Provide data persistence with SQLModel ORM.

**Technology**: SQLite, SQLModel, Python 3.11+

### 7.2 Core Tables

- domains
- scan_sessions
- subdomain_history
- security_alerts
- findings
- vulnerabilities
- cve_mappings
- finding_groups
- jobs

### 7.3 Files

| File | Purpose |
|------|---------|
| `src/data/database/sqlmodel_manager.py` | Database operations |
| `src/data/models/job.py` | Job model |

---

## 8. Data Flow Patterns

### 8.1 Async Scan Flow

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
    - Poll database for pending jobs (every 2s)
    - Claim job atomically (tracks worker_id)
    - Update scan status to "running"
    - Execute 8-step workflow:
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

---

## 9. Background Workers

### 9.1 Scan Worker

**File**: `workers/scan_worker.py`

**Features**:
- Database polling for jobs
- Stale job recovery on startup
- Graceful shutdown handling
- Worker ID tracking
- Job completion tracking

**Run**:
```bash
python -m workers.scan_worker
```

**Multiple Workers**:
```bash
# Terminal 1
python -m workers.scan_worker

# Terminal 2
python -m workers.scan_worker

# Terminal 3
python -m workers.scan_worker
```

Jobs are distributed via atomic database claiming.

---

## 10. File Reference by Layer

### Layer 1: API
```
src/api/
├── main.py
├── dependencies.py
├── routes/
│   ├── domains.py
│   ├── scans.py
│   ├── findings.py
│   ├── jobs.py
│   └── health.py
└── schemas/
```

### Layer 2: Orchestrator
```
src/orchestrator/
├── domain_service.py
├── scan_service.py
├── scan_workflow_orchestrator.py
├── findings_service.py
├── job_service.py
├── health_service.py
└── exceptions.py
```

### Layer 3: Job Queue
```
src/data/models/job.py
src/data/database/sqlmodel_manager.py (job methods)
workers/scan_worker.py
```

### Layer 4: Tools
```
src/tools/
├── subfinder/
├── naabu/
├── dnsx/
├── httpx/
├── tlsx/
├── nmap/
└── nuclei/
```

### Layer 5: Analysis
```
src/analysis/
├── analysis_service.py
├── scoring/
│   └── risk_scorer.py
└── detectors/
    ├── port_detector.py
    └── service_detector.py
```

### Layer 6: Database
```
src/data/
├── database/
│   └── sqlmodel_manager.py
└── models/
    └── job.py
```

### Additional Components
```
src/frontend/       # Web dashboard
src/mcp/            # MCP server for Claude Code
src/utils/          # Utilities
```

---

## 11. Best Practices

### 11.1 Layer Boundaries

- API Layer should only handle HTTP concerns
- Orchestrator Layer contains all business logic
- Tools Layer only executes external tools
- Analysis Layer only handles vulnerability detection
- Database Layer only handles persistence

### 11.2 Adding New Features

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

### 11.3 Error Handling

- API Layer: Return appropriate HTTP status codes
- Orchestrator Layer: Raise domain-specific exceptions
- Workers: Log errors and mark jobs as failed
- Database Layer: Handle constraint violations

---

**Last Updated**: January 29, 2026
**Architecture Version**: 6-Layer API-Only with Database Job Queue
