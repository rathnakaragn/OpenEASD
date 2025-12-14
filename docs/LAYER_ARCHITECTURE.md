# OpenEASD Layer Architecture Guide

**Version**: 2.1
**Last Updated**: December 4, 2025
**Status**: Production-Ready (6-Layer API-Only Architecture)

> **New in v2.1**: Added Job persistence (database-backed queue), ScanWorkflowOrchestrator (8-step workflow), stale job recovery, and worker ID tracking.
>
> **New in v2.0**: Removed CLI Layer, added ZeroMQ Messaging Layer for async job processing. API now supports full CRUD operations.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Layer 1: API Layer](#2-layer-1-api-layer-full-crud-rest)
3. [Layer 2: Service Layer](#3-layer-2-service-layer-business-logic)
4. [Layer 3: Messaging Layer](#4-layer-3-messaging-layer-zeromq)
5. [Layer 4: Analysis Layer](#5-layer-4-analysis-layer-vulnerability-detection)
6. [Layer 5: Tools Layer](#6-layer-5-tools-layer-security-tools)
7. [Layer 6: Database Layer](#7-layer-6-database-layer-persistence)
8. [Data Flow Patterns](#8-data-flow-patterns)
9. [Layer Interactions](#9-layer-interactions)
10. [Background Workers](#10-background-workers)
11. [File Reference](#11-file-reference-by-layer)
12. [Best Practices](#12-best-practices)

---

## 1. Architecture Overview

### 1.1 Six-Layer Stack

OpenEASD implements a **6-layer API-only architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: API Layer (FastAPI)                                    │
│ Purpose: Full CRUD REST API for all operations                  │
│ Access: Remote (HTTP), GET/POST/PUT/DELETE                      │
│ Port: 8000                                                      │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Service Layer                                          │
│ Purpose: Shared business logic for API and workers              │
│ Access: Internal (Python imports)                               │
│ Components: ScanService (CRUD), ScanWorkflowOrchestrator (8-step)│
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: Messaging Layer (ZeroMQ + Job Persistence)             │
│ Purpose: Async job distribution with database-backed queue      │
│ Access: PUSH/PULL sockets (tcp://127.0.0.1:5555)               │
│ Components: JobQueue, Job model, stale recovery                 │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: Analysis Layer                                         │
│ Purpose: Automated vulnerability detection and risk scoring     │
│ Access: Internal (called by Service Layer)                      │
│ Components: RiskScorer, Detectors, Finding models               │
├─────────────────────────────────────────────────────────────────┤
│ Layer 5: Tools Layer                                            │
│ Purpose: Execute external security tools                        │
│ Access: Subprocess execution                                    │
│ Tools: Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap               │
├─────────────────────────────────────────────────────────────────┤
│ Layer 6: Database Layer (SQLite + SQLModel)                     │
│ Purpose: Persistent data storage                                │
│ Access: Internal (SQLModel ORM)                                 │
│ Storage: data/openeasd.db                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Background Workers (workers/scan_worker.py)                     │
│ Purpose: Process scan jobs from ZeroMQ queue                    │
│ Access: Pulls from ZeroMQ, writes to Database                   │
│ Features: Job persistence, stale recovery, worker ID tracking   │
│ Run: python -m workers.scan_worker                              │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Design Principles

1. **Separation of Concerns**: Each layer has specific, well-defined responsibilities
2. **API-First Design**: All operations through REST API, no CLI
3. **Async Processing**: Scans run asynchronously via ZeroMQ job queue
4. **Loose Coupling**: Layers communicate through well-defined interfaces
5. **Dependency Injection**: Services injected at runtime
6. **Single Responsibility**: Each component does one thing well
7. **Extensibility**: Easy to add new detectors, tools, or endpoints

### 1.3 Technology Stack

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| API | FastAPI | 0.109+ | Async web framework |
| API | Pydantic | 2.5+ | Data validation |
| API | Uvicorn | 0.27+ | ASGI server |
| Service | Python | 3.11+ | Business logic |
| Messaging | ZeroMQ | 25.0+ | Job queue (PUSH/PULL) |
| Analysis | Python | 3.11+ | Vulnerability detection |
| Tools | Subprocess | stdlib | Tool execution |
| Database | SQLModel | - | ORM layer |
| Database | SQLite | 3.x | Embedded database |

### 1.4 Current Status

- **Implementation**: 100% complete (all 6 layers)
- **Test Coverage**: 79% (2,928/3,696 statements)
- **Tests Passing**: 318+ (API-only)
- **API Endpoints**: 15+ endpoints (full CRUD)
- **Background Workers**: 1 (scan_worker.py)
- **Database Tables**: 15+ tables
- **Security Tools**: 6 integrated (Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap)

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

### 2.2 Responsibilities

#### Core Responsibilities
- **HTTP Request Handling**: Parse and validate incoming HTTP requests
- **Request Validation**: Pydantic v2 schema validation
- **CORS Configuration**: Cross-origin request handling
- **API Documentation**: Auto-generated OpenAPI/Swagger docs
- **Response Formatting**: JSON serialization with proper status codes
- **Error Handling**: HTTP exception handling with proper codes
- **Job Queue Integration**: Push scan jobs to ZeroMQ for async processing

#### Async Scan Pattern
- POST /api/v1/scans creates scan record and pushes job to ZeroMQ
- Returns 202 Accepted immediately with scan_id
- Client polls GET /api/v1/scans/{scan_id} for status updates
- Worker processes job and updates status in database

### 2.3 High-Level Functions

The API Layer exposes the following high-level functions:

#### Domain Operations (Full CRUD)
- `list_domains()` - GET /api/v1/domains - Retrieve paginated list of all domains
- `create_domain()` - POST /api/v1/domains - Create a new domain
- `get_domain()` - GET /api/v1/domains/{domain} - Get detailed information for a specific domain
- `update_domain()` - PUT /api/v1/domains/{domain} - Update domain settings
- `delete_domain()` - DELETE /api/v1/domains/{domain} - Remove a domain

#### Scan Operations (Async)
- `list_scans()` - GET /api/v1/scans - Retrieve paginated list of scan sessions
- `create_scan()` - POST /api/v1/scans - Create and queue a new scan (returns 202)
- `get_scan()` - GET /api/v1/scans/{scan_id} - Get status and details of a specific scan
- `get_scan_results()` - GET /api/v1/scans/{scan_id}/results - Get complete results from a scan

#### Finding Operations
- `list_findings()` - GET /api/v1/findings - Retrieve findings with filtering
- `get_finding()` - GET /api/v1/findings/{id} - Get detailed finding information
- `get_finding_statistics()` - GET /api/v1/findings/statistics/summary - Get finding summaries

#### Health & Monitoring
- `health_check()` - GET /api/v1/health - Verify API and database connectivity

### 2.4 Key Components

#### FastAPI Application
**File**: `src/api/main.py` (111 lines)

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="OpenEASD API",
    description="External Attack Surface Detection API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "PATCH"],
    allow_headers=["*"]
)

# Include routers
app.include_router(health_router, prefix="/api/v1", tags=["health"])
app.include_router(domains_router, prefix="/api/v1/domains", tags=["domains"])
app.include_router(scans_router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(findings_router, prefix="/api/v1/findings", tags=["findings"])
```

#### Dependency Injection
**File**: `src/api/dependencies.py` (145 lines)

```python
from fastapi import Depends, HTTPException, status
from sqlmodel import Session

def get_db_manager() -> SQLModelManager:
    """Get database manager instance."""
    db = SQLModelManager()
    db.initialize()
    try:
        yield db
    finally:
        db.close()

def get_domain_service(
    db: SQLModelManager = Depends(get_db_manager)
) -> DomainService:
    """Get domain service with injected database."""
    return DomainService(db)

def get_alert_service(
    db: SQLModelManager = Depends(get_db_manager)
) -> AlertService:
    """Get alert service with injected database."""
    return AlertService(db)
```

### 2.4 API Endpoints

#### Health Check
```
GET /api/v1/health
Response: { "status": "healthy", "version": "2.0.0", "database": "connected" }
```

#### Domain Management
```
GET /api/v1/domains              # List all domains
GET /api/v1/domains/{domain}     # Get domain details
```

#### Scan Management
```
GET /api/v1/scans                        # List scans
GET /api/v1/scans/{scan_id}              # Get scan status
GET /api/v1/scans/{scan_id}/results      # Get scan results
```

#### Alerts/Findings
```
GET /api/v1/alerts                       # List alerts
GET /api/v1/alerts/statistics            # Get statistics
GET /api/v1/findings                     # List findings
GET /api/v1/findings/{finding_id}        # Get finding details
PATCH /api/v1/findings/{finding_id}/status  # Update status (requires API key)
```

### 2.5 Code Examples

#### Example 1: Route Handler with Dependency Injection
**File**: `src/api/routes/domains.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from src.api.schemas.domain import DomainListResponse
from src.services.domain_service import DomainService
from src.api.dependencies import get_domain_service

router = APIRouter()

@router.get("", response_model=DomainListResponse)
async def list_domains(
    limit: int = Query(20, ge=1, le=100),
    primary_only: bool = False,
    service: DomainService = Depends(get_domain_service)
):
    """
    List all domains with optional filtering.

    - **limit**: Maximum domains to return (1-100)
    - **primary_only**: Only return primary domains
    """
    try:
        result = service.list_domains(limit=limit, primary_only=primary_only)
        return DomainListResponse(
            domains=result['domains'],
            total_count=len(result['domains'])
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list domains: {str(e)}"
        )
```

#### Example 2: Pydantic Schema Validation
**File**: `src/api/schemas/domain.py`

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List

class DomainResponse(BaseModel):
    """Schema for domain response."""
    domain: str = Field(..., description="Domain name")
    is_primary: bool = Field(..., description="Primary domain flag")
    scan_count: int = Field(0, description="Number of scans performed")
    last_scanned_at: Optional[str] = Field(None, description="Last scan timestamp")
    subdomain_count: int = Field(0, description="Number of subdomains")

    class Config:
        from_attributes = True  # Pydantic v2

class DomainListResponse(BaseModel):
    """Schema for domain list response."""
    domains: List[DomainResponse]
    total_count: int = Field(..., description="Total number of domains")
```

#### Example 3: API Key Authentication
**File**: `src/api/middleware/auth.py`

```python
from fastapi import Request, HTTPException, status
import hashlib

async def verify_api_key(request: Request, db: SQLModelManager):
    """Verify API key from X-API-Key header."""
    api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )

    # Hash the provided key
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Look up in database
    stored_key = db.get_api_key_by_hash(key_hash)

    if not stored_key or not stored_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key"
        )

    # Update last_used_at
    db.update_api_key_last_used(stored_key.id)

    return stored_key
```

### 2.6 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/api/main.py` | 111 | FastAPI app initialization |
| `src/api/dependencies.py` | 145 | Dependency injection |
| `src/api/routes/health.py` | 38 | Health check endpoint |
| `src/api/routes/domains.py` | 200+ | Domain endpoints |
| `src/api/routes/scans.py` | 200+ | Scan endpoints |
| `src/api/routes/alerts.py` | 100+ | Alert endpoints |
| `src/api/routes/findings.py` | 260 | Findings endpoints |
| `src/api/schemas/domain.py` | 104 | Domain schemas |
| `src/api/schemas/scan.py` | 100+ | Scan schemas |
| `src/api/schemas/finding.py` | 88 | Finding schemas |
| `src/api/schemas/alert.py` | 91 | Alert schemas |

---

## 3. Layer 2: Service Layer (Business Logic)

### 3.1 Purpose

Provide **shared business logic** for the API layer. The service layer acts as an orchestration layer, coordinating between multiple components and enforcing business rules.

**Key Characteristics**:
- Domain logic and validation
- Orchestrates complex workflows via ScanWorkflowOrchestrator
- Handles errors and logging
- Dependency injection ready
- Clear separation: ScanService (CRUD) vs ScanWorkflowOrchestrator (execution)

### 3.2 Responsibilities

#### Core Responsibilities
- **Domain CRUD**: Create, read, update, delete domains with validation
- **Scan Orchestration**: Coordinate tool execution and result storage
- **Alert Management**: Aggregate and filter security alerts
- **Analysis Coordination**: Trigger vulnerability detection after scans
- **Business Rules**: Enforce domain uniqueness, validation, etc.
- **Data Transformation**: Convert between database and API formats
- **Error Handling**: Catch and transform exceptions
- **Logging**: Record operations for debugging

### 3.3 High-Level Functions

The Service Layer provides the following high-level business functions:

#### DomainService Functions
- `create_domain()` - Add new domain with validation and duplicate checking
- `list_domains()` - Get domains with filtering and subdomain counts
- `get_domain()` - Get domain details with scan history
- `update_domain()` - Modify domain properties (primary flag, contact, frequency)
- `delete_domain()` - Remove domain with cascade deletion preview

#### ScanService Functions (CRUD Operations)
- `create_scan()` - Create new scan session
- `get_scan_status()` - Get current scan progress and status
- `get_scan_results()` - Retrieve all scan outputs (subdomains, ports, HTTP data)
- `list_scans()` - Get paginated scan history with filtering
- `update_scan_status()` - Update scan status (pending/running/completed/failed)
- `execute_scan_workflow()` - Delegate to ScanWorkflowOrchestrator

#### ScanWorkflowOrchestrator Functions (NEW - Workflow Execution)
The 8-step scan workflow, extracted from ScanService:
- `step1_discover_subdomains()` - Subfinder for subdomain enumeration
- `step2_resolve_dns()` - Dnsx for DNS resolution and IP filtering
- `step3_scan_ports()` - Naabu for port scanning
- `step4_probe_http()` - Httpx for web service detection
- `step5_verify_tls()` - Tlsx for TLS verification on non-web ports
- `step6_detect_services()` - Nmap for service identification
- `step7_detect_vulnerabilities()` - Nmap for vulnerability scanning
- `step8_analyze()` - Risk scoring and finding generation
- `execute_workflow()` - Run complete 8-step workflow

#### AlertService Functions
- `list_alerts()` - Get alerts with severity/domain filtering
- `get_alert()` - Retrieve specific alert details
- `get_alert_statistics()` - Calculate alert counts by severity
- **Note**: Delegates to Analysis Layer's `AlertManagementService`

#### AnalysisService Functions (in Analysis Layer)
- `run_analysis()` - Execute vulnerability detection on scan results
- `get_findings()` - Retrieve findings with risk score filtering
- `update_finding_status()` - Change finding status (open/resolved/false_positive)

### 3.4 Key Components

#### DomainService
**File**: `src/services/domain_service.py` (200+ lines)

**Responsibilities**:
- Validate domain format
- Check for duplicates
- Add/update/delete domains
- List domains with filtering
- Get domain details with subdomain count

**Methods**:
```python
class DomainService:
    def create_domain(domain, is_primary, contact_email, scan_frequency) -> Dict
    def list_domains(limit, primary_only) -> Dict
    def get_domain(domain_name) -> Dict
    def update_domain(domain, updates) -> Dict
    def delete_domain(domain_name, force) -> Dict
```

#### ScanService
**File**: `src/services/scan_service.py` (~520 lines after refactor)

**Responsibilities**:
- Create scan sessions (CRUD)
- Track scan status
- Delegate workflow execution to ScanWorkflowOrchestrator

**Methods**:
```python
class ScanService:
    def create_scan(domains, scan_type, tool_name) -> Dict
    def get_scan_status(scan_id) -> Dict
    def get_scan_results(scan_id) -> Dict
    def list_scans(limit, domain_filter) -> Dict
    def update_scan_status(scan_id, status, error) -> None
    def execute_scan_workflow(scan_id, domain, timeout) -> Dict
```

#### ScanWorkflowOrchestrator (NEW)
**File**: `src/services/scan_workflow_orchestrator.py` (~600 lines)

**Responsibilities**:
- Execute 8-step scan workflow
- Coordinate security tool execution
- Handle port categorization (web vs non-web)
- Service severity mapping
- Integration with analysis layer

**Methods**:
```python
class ScanWorkflowOrchestrator:
    def step1_discover_subdomains(domain, scan_id, timeout) -> List[str]
    def step2_resolve_dns(subdomains, timeout) -> Tuple[List, List]
    def step3_scan_ports(active_subdomains, scan_id, timeout) -> List[Dict]
    def step4_probe_http(ports_found, timeout) -> Tuple[List, Dict]
    def step5_verify_tls(ports_found, timeout) -> Dict
    def step6_detect_services(non_web_ports) -> Dict
    def step7_detect_vulnerabilities(nmap_service_results) -> Dict
    def step8_analyze(scan_id, scan_data) -> Optional[Dict]
    def execute_workflow(scan_id, domain, timeout) -> Dict
```

#### AlertService
**File**: `src/services/alert_service.py` (117 lines)

**Responsibilities**:
- List alerts with filtering
- Get alert by ID
- Get alert statistics
- Delegates to Analysis Layer's AlertManagementService

**Methods**:
```python
class AlertService:
    def list_alerts(limit, severity, domain, min_severity) -> Dict
    def get_alert(alert_id) -> Dict
    def get_alert_statistics() -> Dict
```

### 3.4 Code Examples

#### Example 1: Service Initialization with Dependency Injection
**File**: `src/services/domain_service.py`

```python
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain

class DomainService:
    """Service for managing domains."""

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize domain service.

        Args:
            db_manager: Database manager instance (injected)
        """
        self.db = db_manager

    def create_domain(
        self,
        domain: str,
        is_primary: bool = False,
        contact_email: Optional[str] = None,
        scan_frequency: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new domain with validation.

        Business Rules:
        - Domain format must be valid
        - Domain must not already exist
        - Scan frequency must be valid enum
        """
        # Validate domain format
        domain = validate_domain(domain)

        # Check if domain already exists
        if self.db.domain_exists(domain):
            raise ValueError(f'Domain {domain} already exists')

        # Add domain to database
        self.db.add_domain(
            domain=domain,
            is_primary=is_primary,
            contact_email=contact_email,
            scan_frequency=scan_frequency
        )

        # Get the created domain
        result = self.db.get_domains(domain_name=domain, limit=1)

        return {
            'success': True,
            'domain': result['domains'][0] if result['domains'] else None
        }
```

#### Example 2: Scan Orchestration Workflow
**File**: `src/services/scan_service.py`

```python
from src.tools.runners import run_subfinder, run_naabu, run_dnsx, run_httpx
from src.analysis.analysis_service import AnalysisService

class ScanService:
    """Service for orchestrating scans."""

    def __init__(self, db_manager: SQLModelManager, enable_analysis: bool = True):
        self.db = db_manager
        self.analysis_service = AnalysisService(db_manager) if enable_analysis else None

    def execute_scan(self, domain: str) -> Dict[str, Any]:
        """
        Execute complete scan workflow.

        Workflow:
        1. Validate domain
        2. Create scan session
        3. Run tools (Subfinder → Naabu → Dnsx → Httpx)
        4. Store results in database
        5. Trigger analysis layer
        6. Return scan results
        """
        # Step 1: Validate domain
        domain = validate_domain(domain)

        # Step 2: Create scan session
        scan = self.db.create_scan_session(
            domain=domain,
            status='running'
        )

        try:
            # Step 3: Run tools sequentially
            logger.info(f"Running subfinder for {domain}")
            subdomains = run_subfinder(domain)

            logger.info(f"Running naabu on {len(subdomains)} subdomains")
            ports = run_naabu(subdomains)

            logger.info(f"Running dnsx on subdomains")
            dns_results = run_dnsx(subdomains)

            logger.info(f"Running httpx on subdomains")
            web_data = run_httpx(subdomains)

            # Step 4: Store results
            self.db.store_subfinder_results(scan.id, subdomains)
            self.db.store_naabu_results(scan.id, ports)
            self.db.store_dnsx_results(scan.id, dns_results)
            self.db.store_httpx_results(scan.id, web_data)

            # Step 5: Trigger analysis
            if self.analysis_service:
                analysis_results = self.analysis_service.analyze_scan(
                    scan.id,
                    {
                        'subdomains': subdomains,
                        'ports': ports,
                        'dns': dns_results,
                        'web': web_data
                    }
                )
                logger.info(f"Analysis complete: {len(analysis_results['findings'])} findings")

            # Update scan status
            self.db.update_scan_status(scan.id, 'completed')

            # Step 6: Return results
            return {
                'success': True,
                'scan_id': scan.id,
                'subdomains_count': len(subdomains),
                'ports_count': len(ports),
                'findings_count': len(analysis_results['findings']) if self.analysis_service else 0
            }

        except Exception as e:
            # Handle errors
            self.db.update_scan_status(scan.id, 'failed', error_message=str(e))
            logger.error(f"Scan failed: {e}")
            raise
```

#### Example 3: Service Layer Calling Analysis Layer
**File**: `src/services/alert_service.py`

```python
from src.analysis.alert_service import AlertManagementService

class AlertService:
    """Service for managing security alerts."""

    def __init__(self, db_manager: SQLModelManager):
        self.db = db_manager
        # Delegate to Analysis Layer
        self.alert_mgmt_service = AlertManagementService(db_manager)

    def list_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        domain: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List security alerts with filtering.

        Delegates to Analysis Layer's AlertManagementService
        for advanced risk scoring and filtering.
        """
        # Use analysis layer service
        result = self.alert_mgmt_service.get_alerts(
            limit=limit,
            severity=severity,
            domain=domain,
            min_severity=min_severity
        )

        # Return in expected format
        return {
            'success': True,
            'alerts': result.get('alerts', []),
            'total': result.get('total', 0)
        }
```

### 3.5 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/services/domain_service.py` | 200+ | Domain business logic |
| `src/services/scan_service.py` | 550+ | Scan orchestration |
| `src/services/alert_service.py` | 117 | Alert management |
| `src/analysis/analysis_service.py` | 350+ | Analysis orchestration |

---

## 4. Layer 3: Messaging Layer (ZeroMQ + Job Persistence)

### 4.1 Purpose

Provide **async job distribution** between the API layer and background workers using ZeroMQ PUSH/PULL pattern with **database-backed job persistence**. This enables non-blocking scan operations where the API can return immediately while workers process jobs, with crash recovery support.

**Key Characteristics**:
- ZeroMQ PUSH/PULL pattern for job distribution
- **Database-persisted jobs** (jobs saved to SQLite BEFORE ZeroMQ push)
- Multiple workers can process jobs in parallel
- Automatic job distribution across workers
- **Stale job recovery** (jobs stuck >30 minutes are recovered)
- **Worker ID tracking** for job claiming

### 4.2 Responsibilities

#### Core Responsibilities
- **Job Queue Management**: Push/pull jobs between API and workers
- **Socket Management**: PUSH socket for API, PULL socket for workers
- **Job Persistence**: Save jobs to database before ZeroMQ push (NEW)
- **Job Lifecycle Tracking**: Track job state through lifecycle (NEW)
- **Stale Job Recovery**: Detect and recover stuck jobs (NEW)
- **Worker Coordination**: Track which worker is processing which job (NEW)
- **Connection Handling**: Connect, bind, and close sockets
- **Configuration**: Configurable addresses and timeouts

### 4.3 High-Level Functions

The Messaging Layer provides **job distribution** functions. It connects the API layer to background workers.

**Key Pattern**: API pushes jobs → ZeroMQ distributes → Workers pull and process → Database stores results

#### Job Queue Operations
- `push_job()` - Push a job to the queue (API side)
- `pull_job()` - Pull a job from the queue (Worker side)
- `complete_job()` - Mark job as completed/failed (NEW)
- `connect_push()` - Connect PUSH socket (API server)
- `connect_pull()` - Bind PULL socket (Worker)
- `set_worker_id()` - Set worker ID for job claiming (NEW)
- `close()` - Close all sockets

#### Job Persistence (NEW - `src/data/models/job.py`)

Jobs are persisted to SQLite BEFORE being pushed to ZeroMQ:

```python
class Job(SQLModel, table=True):
    id: str                    # Primary key (UUID)
    job_type: str              # "scan", "analysis", etc.
    payload: Optional[str]     # JSON payload
    status: str                # pending/queued/processing/completed/failed/cancelled
    scan_id: Optional[str]     # Associated scan session ID
    worker_id: Optional[str]   # Worker that claimed the job
    created_at: datetime       # Job creation time
    queued_at: datetime        # When pushed to ZeroMQ
    started_at: datetime       # When worker started processing
    completed_at: datetime     # When job finished
    error_message: Optional[str]  # Error details if failed
    retry_count: int           # Number of retry attempts (default: 0)
    max_retries: int           # Maximum retry limit (default: 3)
    priority: int              # Job priority (lower = higher, default: 100)
```

#### Job Lifecycle States
```
pending -> queued -> processing -> completed
                  ↘            ↗
                    failed/cancelled
```

#### SQLModelManager Job Methods (10+ methods)
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
- `cleanup_old_jobs()` - Remove old completed jobs (>7 days)

#### Job Format
```json
{
  "id": "uuid-string",
  "type": "scan",
  "payload": {
    "scan_id": "scan-uuid",
    "domain": "example.com",
    "timeout": 300
  },
  "timestamp": "2025-12-03T10:00:00Z"
}
```

#### Configuration Options
- `push_address` - Address for PUSH socket (default: tcp://127.0.0.1:5555)
- `pull_address` - Address for PULL socket (default: tcp://127.0.0.1:5555)
- `send_timeout` - Timeout for send operations (default: 5000ms)
- `recv_timeout` - Timeout for receive operations (default: 1000ms)
- `high_water_mark` - Maximum queued messages (default: 1000)

### 4.4 Architecture Pattern

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   API Server    │         │     ZeroMQ      │         │    Workers      │
│                 │         │                 │         │                 │
│  POST /scans    │  PUSH   │   tcp://5555    │  PULL   │ scan_worker.py  │
│  ─────────────► │ ──────► │                 │ ──────► │                 │
│                 │         │   Job Queue     │         │  Process Jobs   │
│  Returns 202    │         │                 │         │  Update DB      │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                                                       │
        │                      ┌──────────────────┐             │
        └─────────────────────►│    Database      │◄────────────┘
                              │   (SQLite)       │
                              │  Status Updates  │
                              └──────────────────┘
```

### 4.5 Code Examples

#### Example 1: Job Queue Class
**File**: `src/messaging/job_queue.py`

```python
import zmq
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

class JobQueue:
    def __init__(self, config=None):
        self.config = config or MessagingConfig()
        self.context = zmq.Context()
        self.push_socket = None
        self.pull_socket = None

    def connect_push(self) -> None:
        """Connect PUSH socket (API server side)."""
        self.push_socket = self.context.socket(zmq.PUSH)
        self.push_socket.setsockopt(zmq.SNDTIMEO, self.config.send_timeout)
        self.push_socket.connect(self.config.push_address)

    def connect_pull(self) -> None:
        """Bind PULL socket (worker side)."""
        self.pull_socket = self.context.socket(zmq.PULL)
        self.pull_socket.setsockopt(zmq.RCVTIMEO, self.config.recv_timeout)
        self.pull_socket.bind(self.config.pull_address)

    def push_job(self, job_type: str, payload: Dict) -> str:
        """Push a job to the queue."""
        job = {
            "id": str(uuid.uuid4()),
            "type": job_type,
            "payload": payload,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.push_socket.send_json(job)
        return job["id"]

    def pull_job(self, block: bool = True) -> Optional[Dict]:
        """Pull a job from the queue."""
        flags = 0 if block else zmq.NOBLOCK
        return self.pull_socket.recv_json(flags=flags)
```

#### Example 2: Worker Process with Job Persistence (NEW)
**File**: `workers/scan_worker.py`

```python
class ScanWorker:
    def __init__(self):
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"  # Unique worker ID
        self.db_manager = SQLModelManager()
        self.db_manager.initialize()

        # Initialize job queue with database manager
        self.job_queue = JobQueue(db_manager=self.db_manager)
        self.job_queue.set_worker_id(self.worker_id)

        self.scan_service = ScanService(db_manager=self.db_manager)
        self._last_recovery_check = 0

    def start(self):
        """Start processing jobs."""
        self.job_queue.connect_pull()
        self._recover_stale_jobs()  # Recover on startup

        while self.running:
            self._periodic_recovery_check()  # Check every 60 seconds
            job = self.job_queue.pull_job(block=True)
            if job:
                self._process_job(job)

    def _process_scan_job(self, job_id, payload):
        scan_id = payload.get("scan_id")
        domain = payload.get("domain")

        # Update status to running
        self.scan_service.update_scan_status(scan_id, "running")

        # Execute 8-step workflow
        self.scan_service.execute_scan_workflow(scan_id, domain)

        # Update status to completed
        self.scan_service.update_scan_status(scan_id, "completed")

        # Mark job as completed
        self.job_queue.complete_job(job_id, success=True)

    def _recover_stale_jobs(self):
        """Recover jobs stuck in processing (>30 min)."""
        stale_jobs = self.db_manager.get_stale_jobs(stale_minutes=30)
        for job in stale_jobs:
            if self.db_manager.retry_job(job['id']):
                logger.info(f"Job {job['id']} reset for retry")
            else:
                self.db_manager.complete_job(job['id'], success=False,
                    error_message="Max retries exceeded")
```

### 4.6 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/messaging/__init__.py` | 10+ | Module exports |
| `src/messaging/config.py` | 30+ | ZeroMQ configuration |
| `src/messaging/job_queue.py` | 150+ | Job queue with DB integration |
| `src/data/models/job.py` | 45 | Job persistence model (NEW) |
| `workers/__init__.py` | 5+ | Workers module |
| `workers/scan_worker.py` | 310+ | Scan job processor with recovery |

---

## 5. Layer 4: Analysis Layer (Vulnerability Detection)

### 5.1 Purpose

Provide **automated vulnerability detection and risk scoring** for scan results. The analysis layer transforms raw scan data into actionable security findings.

**Key Characteristics**:
- Deterministic risk scoring (0-100)
- Multiple detectors (extensible pattern)
- Finding deduplication
- CVE enrichment capability
- Status lifecycle management

### 5.2 Responsibilities

#### Core Responsibilities
- **Vulnerability Detection**: Analyze scan data with multiple detectors
- **Risk Scoring**: Calculate 0-100 risk scores with breakdown
- **Severity Mapping**: Map risk scores to severity levels
- **Finding Deduplication**: Merge duplicate findings
- **Evidence Collection**: Gather technical evidence
- **Remediation Guidance**: Provide fix recommendations
- **Status Tracking**: Manage finding lifecycle
- **CVE Mapping**: Link findings to known CVEs

### 5.3 High-Level Functions

The Analysis Layer provides the following high-level functions:

#### Vulnerability Detection Functions
- `run_analysis()` - Execute all enabled detectors on scan results
- `detect_port_vulnerabilities()` - Analyze open ports for security risks
- `detect_subdomain_takeover()` - Check for subdomain takeover risks
- `detect_tls_vulnerabilities()` - Analyze TLS/SSL configurations
- `detect_technology_stack()` - Identify technologies and known CVEs

#### Risk Scoring Functions
- `calculate_risk_score()` - Compute 0-100 risk score with breakdown
- `score_finding()` - Score individual finding with base + context + exposure
- `map_severity()` - Convert risk score to severity (critical/high/medium/low/info)
- `get_score_breakdown()` - Return detailed scoring rationale

#### Finding Management Functions
- `create_finding()` - Create new finding with all metadata
- `deduplicate_findings()` - Merge duplicate findings across scans
- `get_findings()` - Retrieve findings with filtering (severity, status, asset)
- `update_finding_status()` - Change status (open → acknowledged → resolved → false_positive)
- `get_finding_statistics()` - Calculate risk distribution and severity counts

#### Alert Management Functions (AlertManagementService)
- `create_alert_from_scan()` - Convert scan result to finding
- `create_alert_batch()` - Process multiple alerts at once
- `store_alerts()` - Persist findings to database
- `get_alerts()` - Retrieve alerts with filtering (backward compatible)

#### CVE Integration Functions
- `map_cve_to_finding()` - Link finding to CVE identifier
- `enrich_with_cve_data()` - Add CVE details to finding
- `get_cve_mappings()` - List all CVE mappings for a finding

### 5.4 Key Components

#### RiskScorer
**File**: `src/analysis/scoring/risk_scorer.py` (250+ lines)

**Purpose**: Calculate deterministic risk scores (0-100)

**Scoring Algorithm**:
```
Total Risk Score = Base Score (0-40) + Context Score (0-40) + Exposure Score (0-20)

Where:
- Base Score: Inherent risk of finding type
- Context Score: Business context and criticality
- Exposure Score: Public accessibility and exploitability
```

**Severity Mapping**:
- **Critical**: 80-100 (immediate action required)
- **High**: 60-79 (urgent attention needed)
- **Medium**: 40-59 (should be addressed)
- **Low**: 20-39 (minor risk)
- **Info**: 0-19 (informational)

#### PortVulnerabilityDetector
**File**: `src/analysis/detectors/port_detector.py` (250+ lines)

**Purpose**: Detect port-based vulnerabilities

**Detection Rules**:
- Database ports (3306, 5432, 27017, 6379) → Critical
- High-risk services (23, 21, 3389, 5900) → High
- Admin interfaces (2082, 2083, 8443, 10000) → Medium
- Common web ports (80, 443) → Low

#### AnalysisService
**File**: `src/analysis/analysis_service.py` (350+ lines)

**Purpose**: Orchestrate analysis workflow

**Workflow**:
1. Load enabled detectors
2. Run detectors on scan data
3. Score findings with RiskScorer
4. Deduplicate findings
5. Store findings in database
6. Generate statistics

### 5.4 Code Examples

#### Example 1: Risk Scoring Algorithm
**File**: `src/analysis/scoring/risk_scorer.py`

```python
class RiskScorer:
    """Deterministic risk scoring engine."""

    # Base risk scores by finding type (0-40)
    BASE_RISK_MAP = {
        'database_port_exposed': 40,  # Maximum base risk
        'high_risk_service': 35,
        'admin_interface_exposed': 30,
        'outdated_software': 25,
        'subdomain_discovered': 5,
        'web_port_open': 10
    }

    def score_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score for a finding.

        Returns finding with added fields:
        - risk_score (0-100)
        - severity (critical/high/medium/low/info)
        - score_breakdown (dict with component scores)
        """
        # Component 1: Base score (0-40)
        finding_type = finding.get('finding_type', 'unknown')
        base_score = self.BASE_RISK_MAP.get(finding_type, 15)

        # Component 2: Context score (0-40)
        context_score = self._calculate_context_score(finding)

        # Component 3: Exposure score (0-20)
        exposure_score = self._calculate_exposure_score(finding)

        # Calculate total
        total_score = base_score + context_score + exposure_score
        total_score = min(100, max(0, total_score))  # Clamp to 0-100

        # Map to severity
        severity = self._score_to_severity(total_score)

        # Add to finding
        finding['risk_score'] = total_score
        finding['severity'] = severity
        finding['score_breakdown'] = {
            'base_score': base_score,
            'context_score': context_score,
            'exposure_score': exposure_score,
            'total': total_score
        }

        return finding

    def _calculate_context_score(self, finding: Dict[str, Any]) -> int:
        """Calculate context score based on business criticality."""
        score = 20  # Default

        # Is it a primary domain asset?
        if finding.get('is_primary_domain'):
            score += 10

        # Does it have sensitive data?
        if finding.get('has_sensitive_data'):
            score += 10

        return min(40, score)

    def _calculate_exposure_score(self, finding: Dict[str, Any]) -> int:
        """Calculate exposure score based on accessibility."""
        score = 0

        # Publicly accessible?
        if finding.get('publicly_accessible'):
            score += 10

        # Has authentication?
        if not finding.get('has_authentication'):
            score += 5

        # Known exploits available?
        if finding.get('exploit_available'):
            score += 5

        return min(20, score)

    def _score_to_severity(self, score: int) -> str:
        """Map risk score to severity level."""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'
```

#### Example 2: Port Vulnerability Detector
**File**: `src/analysis/detectors/port_detector.py`

```python
from src.analysis.detectors.base_detector import BaseDetector

class PortVulnerabilityDetector(BaseDetector):
    """Detects vulnerabilities in open ports."""

    # Port classifications
    DATABASE_PORTS = {
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        1433: 'MSSQL'
    }

    HIGH_RISK_PORTS = {
        23: 'Telnet',
        21: 'FTP',
        3389: 'RDP',
        5900: 'VNC',
        22: 'SSH'
    }

    ADMIN_PORTS = {
        2082: 'cPanel',
        2083: 'cPanel SSL',
        8443: 'Plesk',
        10000: 'Webmin'
    }

    def analyze(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze port scan results for vulnerabilities.

        Args:
            scan_data: Dictionary containing 'naabu_results' key

        Returns:
            List of finding dictionaries
        """
        findings = []
        ports = scan_data.get('naabu_results', [])

        for port_result in ports:
            port = port_result.get('port')
            subdomain = port_result.get('subdomain')
            protocol = port_result.get('protocol', 'tcp')

            # Check database ports
            if port in self.DATABASE_PORTS:
                findings.append({
                    'finding_type': 'database_port_exposed',
                    'title': f'{self.DATABASE_PORTS[port]} Database Port Exposed',
                    'description': f'Database port {port} ({self.DATABASE_PORTS[port]}) is publicly accessible on {subdomain}',
                    'affected_asset': subdomain,
                    'port': port,
                    'protocol': protocol,
                    'service_name': self.DATABASE_PORTS[port],
                    'confidence_level': 'high',
                    'remediation': f'Restrict access to port {port} using firewall rules. Only allow connections from trusted IP addresses.',
                    'cwe_id': 'CWE-200',  # Exposure of Sensitive Information
                    'detector': 'PortVulnerabilityDetector',
                    'evidence': {
                        'port': port,
                        'service': self.DATABASE_PORTS[port],
                        'detection_method': 'port_scan'
                    }
                })

            # Check high-risk services
            elif port in self.HIGH_RISK_PORTS:
                findings.append({
                    'finding_type': 'high_risk_service_exposed',
                    'title': f'{self.HIGH_RISK_PORTS[port]} Service Exposed',
                    'description': f'High-risk service on port {port} ({self.HIGH_RISK_PORTS[port]}) detected on {subdomain}',
                    'affected_asset': subdomain,
                    'port': port,
                    'protocol': protocol,
                    'service_name': self.HIGH_RISK_PORTS[port],
                    'confidence_level': 'high',
                    'remediation': f'Disable {self.HIGH_RISK_PORTS[port]} or use VPN/bastion host access only.',
                    'cwe_id': 'CWE-749',  # Exposed Dangerous Method or Function
                    'detector': 'PortVulnerabilityDetector'
                })

            # Check admin interfaces
            elif port in self.ADMIN_PORTS:
                findings.append({
                    'finding_type': 'admin_interface_exposed',
                    'title': f'{self.ADMIN_PORTS[port]} Admin Interface Exposed',
                    'description': f'Administrative interface on port {port} is publicly accessible',
                    'affected_asset': subdomain,
                    'port': port,
                    'protocol': protocol,
                    'service_name': self.ADMIN_PORTS[port],
                    'confidence_level': 'medium',
                    'remediation': 'Implement IP whitelisting or VPN access for admin interfaces.',
                    'detector': 'PortVulnerabilityDetector'
                })

        return findings
```

#### Example 3: Analysis Service Orchestration
**File**: `src/analysis/analysis_service.py`

```python
class AnalysisService:
    """Orchestrates vulnerability detection workflow."""

    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.risk_scorer = RiskScorer()
        self.detectors = self._load_detectors()

    def _load_detectors(self) -> List[BaseDetector]:
        """Load all enabled detectors."""
        detectors = []

        # Port detector
        port_detector = PortVulnerabilityDetector()
        if port_detector.is_enabled():
            detectors.append(port_detector)

        # Add more detectors here as they're developed
        # detectors.append(WebVulnerabilityDetector())
        # detectors.append(TLSVulnerabilityDetector())

        return detectors

    async def analyze_scan_results(
        self,
        scan_id: str,
        scan_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Main analysis workflow.

        Steps:
        1. Run all detectors
        2. Score findings
        3. Deduplicate
        4. Store in database
        5. Generate statistics
        """
        logger.info(f"Starting analysis for scan {scan_id}")

        # Step 1: Run detectors
        all_findings = []
        for detector in self.detectors:
            try:
                findings = detector.analyze(scan_data)
                all_findings.extend(findings)
                logger.info(f"{detector.get_name()} found {len(findings)} findings")
            except Exception as e:
                logger.error(f"Detector {detector.get_name()} failed: {e}")

        # Step 2: Score findings
        scored_findings = []
        for finding in all_findings:
            scored_finding = self.risk_scorer.score_finding(finding)
            scored_findings.append(scored_finding)

        # Step 3: Deduplicate
        unique_findings = self._deduplicate_findings(scored_findings)

        # Step 4: Store in database
        if self.db_manager:
            for finding in unique_findings:
                finding['scan_id'] = scan_id
                finding['id'] = str(uuid.uuid4())
                finding['discovered_at'] = get_ist_now()

            self.db_manager.store_findings(unique_findings)

        # Step 5: Generate statistics
        stats = self._generate_statistics(unique_findings)

        return {
            'scan_id': scan_id,
            'findings_count': len(unique_findings),
            'findings': unique_findings,
            'statistics': stats
        }

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings."""
        seen = {}

        for finding in findings:
            # Create deduplication key
            key = f"{finding['finding_type']}|{finding['affected_asset']}|{finding.get('port', '')}"

            # Keep highest risk score
            if key not in seen or finding['risk_score'] > seen[key]['risk_score']:
                seen[key] = finding

        return list(seen.values())
```

### 5.5 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/analysis/analysis_service.py` | 350+ | Analysis orchestration |
| `src/analysis/scoring/risk_scorer.py` | 250+ | Risk scoring engine |
| `src/analysis/detectors/base_detector.py` | 50+ | Abstract detector |
| `src/analysis/detectors/port_detector.py` | 250+ | Port vulnerability detection |
| `src/analysis/alert_service.py` | 400+ | Alert management |
| `src/analysis/models.py` | 150+ | Finding/Vulnerability models |

---

## 6. Layer 5: Tools Layer (Security Tools)

### 6.1 Purpose

Execute **external security tools** via subprocess and parse their output. The tools layer provides a clean abstraction over command-line security tools.

**Key Characteristics**:
- Direct subprocess execution
- JSON output parsing
- Error handling and timeout management
- Tool-agnostic result format
- No orchestration logic (belongs in Service Layer)

### 6.2 Responsibilities

#### Core Responsibilities
- **Subprocess Execution**: Run external tools with proper arguments
- **JSON Parsing**: Parse tool JSON output into Python objects
- **Error Handling**: Catch timeouts, missing tools, invalid output
- **Timeout Management**: Kill long-running processes
- **Result Standardization**: Convert tool output to common format
- **Logging**: Record tool execution details

### 6.3 High-Level Functions

The Tools Layer provides the following high-level tool execution functions:

#### Subdomain Discovery Functions
- `run_subfinder()` - Execute Subfinder for passive subdomain discovery
  - Returns: List of discovered subdomains
  - Options: Custom resolvers, timeout, sources configuration
- `run_amass()` - Execute Amass for comprehensive subdomain enumeration
  - Returns: Subdomains with IP addresses, ASN, metadata
  - Options: Active/passive mode, data sources

#### Port Scanning Functions
- `run_naabu()` - Execute Naabu for fast port scanning
  - Returns: List of open ports with protocol
  - Options: Port range, rate limiting, timeout
- `run_nmap()` - Execute Nmap for detailed service detection
  - Returns: Ports with service names, versions, OS fingerprinting
  - Options: Scan type, timing, script execution

#### DNS Resolution Functions
- `run_dnsx()` - Execute Dnsx for DNS resolution and validation
  - Returns: DNS records (A, AAAA, CNAME, MX, TXT)
  - Options: Record types, wildcard detection, retry count

#### HTTP Probing Functions
- `run_httpx()` - Execute Httpx for HTTP/HTTPS service probing
  - Returns: HTTP status, title, server, technologies
  - Options: Follow redirects, extract headers, screenshot capture

#### Result Parsing Functions
- `parse_json_output()` - Parse line-delimited JSON from tools
- `parse_xml_output()` - Parse XML output (Nmap) to JSON
- `standardize_results()` - Convert tool-specific format to common schema
- `validate_tool_output()` - Verify output format and completeness

#### Tool Management Functions
- `check_tool_installed()` - Verify tool is available in PATH
- `get_tool_version()` - Get installed tool version
- `validate_tool_args()` - Validate command-line arguments
- `handle_tool_error()` - Process tool errors and timeouts

### 6.4 Integrated Tools

| Tool | Purpose | Output Format | Active | Command |
|------|---------|---------------|--------|---------|
| Subfinder | Passive subdomain discovery | JSON (one per line) | ✅ | `subfinder -d domain -silent -json` |
| Naabu | Fast port scanning | JSON | ✅ | `naabu -host hosts -json -silent` |
| Dnsx | DNS resolution/validation | JSON | ✅ | `dnsx -l hosts -json -silent` |
| Httpx | HTTP/HTTPS probing | JSON | ✅ | `httpx -l urls -json -silent` |
| Amass | Comprehensive subdomain enum | JSON | Module available | `amass enum -d domain -json` |
| Nmap | Service detection | XML → JSON | Module available | `nmap -oX - host` |

### 6.4 Code Examples

#### Example 1: Subfinder Tool Runner
**File**: `src/tools/runners.py`

```python
import subprocess
import json
import logging
from typing import List, Dict, Any
from src.utils.validation import validate_domain

logger = logging.getLogger(__name__)

def run_subfinder(
    domain: str,
    timeout: int = 300,
    resolvers: Optional[str] = None
) -> List[str]:
    """
    Run subfinder to discover subdomains.

    Args:
        domain: Target domain
        timeout: Execution timeout in seconds (default: 300)
        resolvers: Path to custom DNS resolvers file

    Returns:
        List of discovered subdomains

    Raises:
        ValueError: If domain is invalid
        subprocess.TimeoutExpired: If execution times out
        FileNotFoundError: If subfinder is not installed
    """
    # Validate domain
    domain = validate_domain(domain)

    # Build command
    cmd = ['subfinder', '-d', domain, '-silent', '-json']

    if resolvers:
        cmd.extend(['-r', resolvers])

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        # Execute subprocess
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit
        )

        # Parse JSON output (one JSON object per line)
        subdomains = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            try:
                data = json.loads(line)
                if 'host' in data:
                    subdomains.append(data['host'])
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse subfinder output line: {line}")
                continue

        logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
        return subdomains

    except subprocess.TimeoutExpired:
        logger.error(f"Subfinder timed out after {timeout} seconds")
        raise TimeoutError(f"Subfinder execution exceeded {timeout} seconds")

    except FileNotFoundError:
        logger.error("Subfinder not found in PATH")
        raise FileNotFoundError(
            "Subfinder not installed. Install: https://github.com/projectdiscovery/subfinder"
        )

    except Exception as e:
        logger.error(f"Subfinder execution failed: {e}")
        raise
```

#### Example 2: Naabu Port Scanner
**File**: `src/tools/runners.py`

```python
def run_naabu(
    targets: List[str],
    ports: Optional[str] = None,
    top_ports: int = 100,
    timeout: int = 600
) -> List[Dict[str, Any]]:
    """
    Run naabu for fast port scanning.

    Args:
        targets: List of hosts/IPs to scan
        ports: Specific ports to scan (e.g., "80,443,8080-8090")
        top_ports: Number of top ports to scan if ports not specified
        timeout: Execution timeout in seconds

    Returns:
        List of dictionaries with format:
        [
            {
                'host': 'example.com',
                'ip': '1.2.3.4',
                'port': 443,
                'protocol': 'tcp'
            },
            ...
        ]
    """
    if not targets:
        return []

    # Write targets to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(targets))
        targets_file = f.name

    # Build command
    cmd = ['naabu', '-list', targets_file, '-json', '-silent']

    if ports:
        cmd.extend(['-p', ports])
    else:
        cmd.extend(['-top-ports', str(top_ports)])

    logger.info(f"Running naabu on {len(targets)} targets")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output
        port_results = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            try:
                data = json.loads(line)
                port_results.append({
                    'host': data.get('host', ''),
                    'ip': data.get('ip', ''),
                    'port': data.get('port', 0),
                    'protocol': data.get('protocol', 'tcp'),
                    'timestamp': data.get('timestamp', '')
                })
            except json.JSONDecodeError:
                continue

        logger.info(f"Naabu found {len(port_results)} open ports")
        return port_results

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Naabu execution exceeded {timeout} seconds")

    except FileNotFoundError:
        raise FileNotFoundError(
            "Naabu not installed. Install: https://github.com/projectdiscovery/naabu"
        )

    finally:
        # Clean up temp file
        import os
        os.unlink(targets_file)
```

#### Example 3: Httpx Web Prober
**File**: `src/tools/runners.py`

```python
def run_httpx(
    targets: List[str],
    timeout: int = 300,
    follow_redirects: bool = True
) -> List[Dict[str, Any]]:
    """
    Run httpx for HTTP/HTTPS probing.

    Args:
        targets: List of URLs or hosts to probe
        timeout: Execution timeout in seconds
        follow_redirects: Follow HTTP redirects

    Returns:
        List of dictionaries with format:
        [
            {
                'url': 'https://example.com',
                'status_code': 200,
                'title': 'Example Domain',
                'server': 'nginx',
                'content_length': 1256,
                'technologies': ['Nginx', 'PHP'],
                'ip': '93.184.216.34'
            },
            ...
        ]
    """
    if not targets:
        return []

    # Write targets to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(targets))
        targets_file = f.name

    # Build command
    cmd = [
        'httpx',
        '-l', targets_file,
        '-json',
        '-silent',
        '-status-code',
        '-title',
        '-server',
        '-content-length',
        '-tech-detect'
    ]

    if follow_redirects:
        cmd.append('-follow-redirects')

    logger.info(f"Running httpx on {len(targets)} targets")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse JSON output
        web_results = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            try:
                data = json.loads(line)
                web_results.append({
                    'url': data.get('url', ''),
                    'status_code': data.get('status_code', 0),
                    'title': data.get('title', ''),
                    'server': data.get('server', ''),
                    'content_length': data.get('content_length', 0),
                    'technologies': data.get('tech', []),
                    'ip': data.get('host', ''),
                    'timestamp': data.get('timestamp', '')
                })
            except json.JSONDecodeError:
                continue

        logger.info(f"Httpx probed {len(web_results)} web services")
        return web_results

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Httpx execution exceeded {timeout} seconds")

    except FileNotFoundError:
        raise FileNotFoundError(
            "Httpx not installed. Install: https://github.com/projectdiscovery/httpx"
        )

    finally:
        import os
        os.unlink(targets_file)
```

### 6.5 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/tools/runners.py` | 250+ | Main tool runner functions |
| `src/tools/subfinder/__init__.py` | - | Subfinder tool wrapper |
| `src/tools/naabu/__init__.py` | - | Naabu tool wrapper |
| `src/tools/dnsx/__init__.py` | - | Dnsx tool wrapper |
| `src/tools/httpx/__init__.py` | - | Httpx tool wrapper |

---

## 7. Layer 6: Database Layer (Persistence)

### 7.1 Purpose

Provide **persistent data storage** and complex query operations using SQLModel ORM with SQLite backend.

**Key Characteristics**:
- SQLModel ORM (Pydantic + SQLAlchemy)
- SQLite embedded database
- ACID transactions
- IST timezone support
- Index optimization

### 7.2 Responsibilities

#### Core Responsibilities
- **CRUD Operations**: Create, read, update, delete for all entities
- **Relationship Management**: Handle foreign keys and joins
- **Transaction Management**: Ensure ACID properties
- **Query Optimization**: Indexes and efficient queries
- **Timezone Conversion**: All timestamps in IST
- **Data Validation**: Enforce constraints
- **Migration Support**: Schema evolution
- **Connection Pooling**: Manage database connections

### 7.3 High-Level Functions

The Database Layer provides the following high-level data persistence functions:

#### Domain Operations
- `create_domain()` - Insert new domain record with metadata
- `get_domain()` - Retrieve domain by name with relationships
- `list_domains()` - Query domains with pagination and filtering
- `update_domain()` - Modify domain properties
- `delete_domain()` - Remove domain with cascade deletion
- `get_domain_scan_count()` - Count scans for a domain

#### Scan Session Operations
- `create_scan_session()` - Create new scan record with UUID
- `get_scan_session()` - Retrieve scan with all results
- `update_scan_status()` - Change scan status (pending → running → completed)
- `list_scan_sessions()` - Query scans with filtering and ordering
- `get_scan_results()` - Fetch all tool results for a scan
- `delete_scan_session()` - Remove scan and associated data

#### Subdomain Operations
- `store_subdomain_history()` - Record subdomain discovery/changes
- `get_subdomains_by_scan()` - Get all subdomains from a scan
- `get_subdomain_changes()` - Track new/existing/removed subdomains
- `get_subdomain_first_seen()` - Find when subdomain was first discovered

#### Tool Result Operations
- `store_subfinder_results()` - Save Subfinder output
- `store_naabu_results()` - Save Naabu port scan results
- `store_dnsx_results()` - Save Dnsx DNS records
- `store_httpx_results()` - Save Httpx HTTP probe results
- `get_tool_results_by_scan()` - Retrieve all results for a scan

#### Finding Operations (Analysis Layer Models)
- `store_findings()` - Persist findings with risk scores
- `get_finding()` - Retrieve finding by ID with all details
- `get_findings()` - Query findings with filtering (severity, status, asset)
- `update_finding_status()` - Change finding status
- `get_findings_by_scan()` - Get all findings for a scan
- `get_findings_by_asset()` - Get findings for specific asset
- `deduplicate_findings()` - Merge duplicate findings

#### Statistics & Analytics Operations
- `get_database_metrics()` - Get counts of all entity types
- `get_domain_statistics()` - Calculate domain scan stats
- `get_scan_statistics()` - Aggregate scan success/failure rates
- `get_finding_statistics()` - Calculate risk distribution
- `get_alert_statistics()` - Count alerts by severity (backward compatible)

#### Transaction Operations
- `begin_transaction()` - Start database transaction
- `commit_transaction()` - Commit changes
- `rollback_transaction()` - Undo changes on error
- `execute_in_transaction()` - Run multiple operations atomically

#### Utility Operations
- `initialize_database()` - Create tables and indexes
- `get_database_info()` - Get database size and table counts
- `vacuum_database()` - Optimize database file
- `backup_database()` - Create database backup
- `validate_schema()` - Verify schema integrity

### 7.4 Database Schema

```sql
-- Core Tables
domains (
    domain TEXT PRIMARY KEY,
    is_primary BOOLEAN,
    scan_count INTEGER,
    contact_email TEXT,
    scan_frequency TEXT,
    active_scan_enabled BOOLEAN,
    created_at DATETIME,
    last_scanned_at DATETIME
)

scan_sessions (
    id TEXT PRIMARY KEY,  -- UUID
    domain TEXT REFERENCES domains(domain),
    status TEXT,  -- pending, running, completed, failed
    start_time DATETIME,
    end_time DATETIME,
    findings_count INTEGER,
    error_message TEXT
)

subdomain_history (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scan_sessions(id),
    apex_domain TEXT,
    subdomain TEXT,
    status TEXT,  -- new, existing, removed
    first_seen DATETIME,
    last_seen DATETIME,
    tool_source TEXT,
    meta_data TEXT  -- JSON
)

-- Tool Result Tables
subfinder_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    apex_domain TEXT,
    subdomain TEXT,
    discovered_at DATETIME,
    source TEXT,
    raw_json TEXT
)

naabu_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    target_host TEXT,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    discovered_at DATETIME,
    raw_json TEXT
)

-- Analysis Tables (from Analysis Layer)
findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_type TEXT,
    affected_asset TEXT,
    port INTEGER,
    protocol TEXT,
    title TEXT,
    description TEXT,
    service_name TEXT,
    severity TEXT,
    risk_score INTEGER,  -- 0-100
    confidence_level TEXT,
    evidence_json TEXT,
    cwe_id TEXT,
    remediation TEXT,
    detector TEXT,
    score_breakdown_json TEXT,
    status TEXT,  -- open, acknowledged, resolved, false_positive
    false_positive BOOLEAN,
    resolved_at DATETIME,
    resolution_notes TEXT,
    discovered_at DATETIME,
    updated_at DATETIME
)

vulnerabilities (
    id TEXT PRIMARY KEY,
    cve_id TEXT UNIQUE,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cwe_id TEXT,
    vulnerability_type TEXT,
    affected_products_json TEXT,
    exploit_available BOOLEAN,
    exploit_maturity TEXT,
    publicly_disclosed BOOLEAN,
    references_json TEXT,
    discovered_at DATETIME,
    updated_at DATETIME
)

cve_mappings (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id),
    vulnerability_id TEXT REFERENCES vulnerabilities(id),
    confidence INTEGER,
    created_at DATETIME,
    updated_at DATETIME
)

-- Security Tables
api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT UNIQUE,  -- SHA-256 hash
    name TEXT,
    permissions_json TEXT,
    is_active BOOLEAN,
    created_at DATETIME,
    last_used_at DATETIME,
    expires_at DATETIME,
    revoked_at DATETIME
)

audit_logs (
    id TEXT PRIMARY KEY,
    operation TEXT,  -- CREATE, UPDATE, DELETE
    entity_type TEXT,  -- domain, scan, finding
    entity_id TEXT,
    api_key_id TEXT,
    changes_json TEXT,
    timestamp DATETIME,
    ip_address TEXT
)
```

### 7.4 Code Examples

#### Example 1: Database Manager Initialization
**File**: `src/data/database/sqlmodel_manager.py`

```python
from sqlmodel import SQLModel, Session, create_engine
from pathlib import Path

class SQLModelManager:
    """SQLModel implementation of DatabaseManager using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize SQLModel database manager.

        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            config = Config()
            db_path = config.get('database.database_path', 'data/openeasd.db')

        # Create parent directory if needed
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Create SQLite engine
        self.db_url = f"sqlite:///{db_path}"
        self.engine = create_engine(
            self.db_url,
            echo=False,  # Set to True for SQL logging
            connect_args={"check_same_thread": False}  # Allow multi-threading
        )
        self.db_path = db_path

    def initialize(self) -> None:
        """Initialize database and create all tables."""
        # Create all tables from SQLModel metadata
        SQLModel.metadata.create_all(self.engine)

        # Create indexes for performance
        self._create_indexes()

    def _create_indexes(self):
        """Create database indexes for query optimization."""
        with Session(self.engine) as session:
            # Domain indexes
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_domain_primary ON domains(is_primary)"
            ))

            # Scan session indexes
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_scan_domain ON scan_sessions(domain)"
            ))
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_sessions(status)"
            ))

            # Finding indexes
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id)"
            ))
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity)"
            ))
            session.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_finding_asset ON findings(affected_asset)"
            ))

            session.commit()

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self, 'engine') and self.engine:
            self.engine.dispose()
```

#### Example 2: CRUD Operations with Transactions
**File**: `src/data/database/sqlmodel_manager.py`

```python
from sqlmodel import select, func, and_, delete

def create_scan_session(self, domain: str, scan_type: str = 'full') -> ScanSession:
    """
    Create new scan session with transaction.

    Args:
        domain: Domain to scan
        scan_type: Type of scan

    Returns:
        Created ScanSession object
    """
    with Session(self.engine) as session:
        # Create scan session
        scan = ScanSession(
            id=str(uuid.uuid4()),
            domain=domain,
            scan_type=scan_type,
            status='pending',
            start_time=get_ist_now()
        )

        session.add(scan)
        session.commit()
        session.refresh(scan)  # Get updated values

        return scan

def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
    """
    Get complete scan results with related data.

    Uses JOINs to efficiently fetch related data.
    """
    with Session(self.engine) as session:
        # Get scan session
        scan = session.exec(
            select(ScanSession).where(ScanSession.id == scan_id)
        ).first()

        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Get subdomains
        subdomains = session.exec(
            select(SubdomainHistory)
            .where(SubdomainHistory.scan_id == scan_id)
            .order_by(SubdomainHistory.subdomain)
        ).all()

        # Get open ports
        ports = session.exec(
            select(NaabuResult)
            .where(NaabuResult.scan_id == scan_id)
            .order_by(NaabuResult.port)
        ).all()

        # Get findings
        findings = session.exec(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.risk_score.desc())
        ).all()

        return {
            'scan': self._scan_to_dict(scan),
            'subdomains': [self._subdomain_to_dict(s) for s in subdomains],
            'ports': [self._port_to_dict(p) for p in ports],
            'findings': [self._finding_to_dict(f) for f in findings]
        }

def delete_domain(self, domain: str, force: bool = False) -> Dict[str, Any]:
    """
    Delete domain and all related data (cascade).

    Uses transaction to ensure atomicity.
    """
    with Session(self.engine) as session:
        # Check if domain exists
        domain_obj = session.exec(
            select(Domain).where(Domain.domain == domain)
        ).first()

        if not domain_obj:
            raise ValueError(f"Domain {domain} not found")

        # Get deletion counts for reporting
        deleted = {}

        # Delete related data (in order due to foreign keys)

        # 1. Findings
        result = session.exec(
            delete(Finding).where(
                Finding.affected_asset.like(f'%{domain}%')
            )
        )
        deleted['findings'] = result.rowcount
        session.commit()

        # 2. Subdomain history
        result = session.exec(
            delete(SubdomainHistory).where(
                SubdomainHistory.apex_domain == domain
            )
        )
        deleted['subdomain_history'] = result.rowcount
        session.commit()

        # 3. Tool results
        result = session.exec(
            delete(SubfinderResult).where(
                SubfinderResult.apex_domain == domain
            )
        )
        deleted['subfinder_results'] = result.rowcount
        session.commit()

        # 4. Scan sessions
        result = session.exec(
            delete(ScanSession).where(
                ScanSession.domain == domain
            )
        )
        deleted['scan_sessions'] = result.rowcount
        session.commit()

        # 5. Finally delete domain
        session.delete(domain_obj)
        session.commit()
        deleted['domain'] = 1

        return {
            'success': True,
            'deleted': deleted,
            'total_records': sum(deleted.values())
        }
```

#### Example 3: Complex Queries with Aggregations
**File**: `src/data/database/sqlmodel_manager.py`

```python
def get_domain_statistics(self) -> Dict[str, Any]:
    """Get database-wide statistics with aggregations."""
    with Session(self.engine) as session:
        stats = {}

        # Domain counts
        stats['total_domains'] = session.exec(
            select(func.count(Domain.domain))
        ).one()

        stats['primary_domains'] = session.exec(
            select(func.count(Domain.domain)).where(
                Domain.is_primary == True
            )
        ).one()

        # Scan counts
        stats['total_scans'] = session.exec(
            select(func.count(ScanSession.id))
        ).one()

        stats['completed_scans'] = session.exec(
            select(func.count(ScanSession.id)).where(
                ScanSession.status == 'completed'
            )
        ).one()

        # Finding counts by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = session.exec(
                select(func.count(Finding.id)).where(
                    Finding.severity == severity
                )
            ).one()
            stats[f'{severity}_findings'] = count

        # Average risk score
        avg_risk = session.exec(
            select(func.avg(Finding.risk_score))
        ).one()
        stats['average_risk_score'] = round(avg_risk, 2) if avg_risk else 0

        return stats
```

### 7.5 Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/data/database/sqlmodel_manager.py` | 1500+ | Database manager implementation |
| `src/data/models/domain.py` | 50+ | Domain SQLModel |
| `src/data/models/scan.py` | 50+ | ScanSession SQLModel |
| `src/data/models/subdomain.py` | 50+ | SubdomainHistory SQLModel |
| `src/data/models/tool_results.py` | 150+ | Tool result SQLModels |
| `src/data/models/api_key.py` | 50+ | APIKey SQLModel |
| `src/data/models/audit_log.py` | 50+ | AuditLog SQLModel |
| `src/analysis/models.py` | 150+ | Finding/Vulnerability SQLModels |

---

## 8. Data Flow Patterns

### 8.1 API GET Request Flow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. HTTP Request                                                  │
│    GET /api/v1/domains?limit=20&primary_only=true               │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. API Layer (src/api/routes/domains.py)                        │
│    - FastAPI parses query parameters                             │
│    - Pydantic validates input (limit: 1-100, primary_only: bool)│
│    - Dependency injection provides DomainService                 │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. Service Layer (src/services/domain_service.py)               │
│    - DomainService.list_domains(limit=20, primary_only=True)    │
│    - Apply business rules                                        │
│    - Call database layer                                         │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. Database Layer (src/data/database/sqlmodel_manager.py)       │
│    - Execute SQL query:                                          │
│      SELECT * FROM domains                                       │
│      WHERE is_primary = true                                     │
│      LIMIT 20                                                    │
│    - Return Domain objects                                       │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. Service Layer (format response)                              │
│    - Convert Domain objects to dictionaries                      │
│    - Add computed fields (subdomain_count, etc.)                 │
│    - Format timestamps                                           │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. API Layer (serialize response)                               │
│    - Pydantic validates response schema                          │
│    - Serialize to JSON                                           │
│    - Add HTTP headers (Content-Type: application/json)           │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. HTTP Response                                                 │
│    200 OK                                                        │
│    Content-Type: application/json                               │
│    {                                                             │
│      "domains": [...],                                           │
│      "total_count": 5                                            │
│    }                                                             │
└──────────────────────────────────────────────────────────────────┘

Time: ~50-200ms (depending on query complexity)
```

### 8.2 CLI Scan Command Flow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. User Command                                                  │
│    $ openeasd scan domain example.com                            │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. CLI Layer (src/cli/main.py)                                  │
│    - Click parses command and arguments                          │
│    - Validate domain format                                      │
│    - Display: "Starting scan of example.com..."                  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. Service Layer (src/services/scan_service.py)                 │
│    - ScanService.execute_scan('example.com')                     │
│    - Create scan session in database                             │
│    - Orchestrate tool execution                                  │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ├────────────────┬────────────────────────┐
                         │                │                        │
                         ▼                ▼                        ▼
┌──────────────────┐ ┌─────────────┐ ┌────────────────────────────┐
│ 4. Tools Layer   │ │ 4. Database │ │ 4. Analysis Layer          │
│                  │ │    Layer    │ │                            │
│ - run_subfinder()│ │             │ │ (triggered after tools)    │
│   Returns: 15    │ │ Store scan  │ │                            │
│   subdomains     │ │ session     │ │                            │
│                  │ │             │ │                            │
│ - run_naabu()    │ │ Store       │ │                            │
│   Returns: 45    │ │ subfinder   │ │                            │
│   open ports     │ │ results     │ │                            │
│                  │ │             │ │                            │
│ - run_dnsx()     │ │ Store       │ │                            │
│   Returns: DNS   │ │ naabu       │ │                            │
│   records        │ │ results     │ │                            │
│                  │ │             │ │                            │
│ - run_httpx()    │ │ Store       │ │                            │
│   Returns: Web   │ │ dnsx/httpx  │ │                            │
│   data           │ │ results     │ │                            │
└──────────────────┘ └─────────────┘ └────────────────────────────┘
         │                  │                        │
         └──────────────────┴────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. Analysis Layer (src/analysis/analysis_service.py)            │
│    - AnalysisService.analyze_scan_results()                      │
│    - Run PortVulnerabilityDetector                               │
│    - RiskScorer.score_finding() for each finding                 │
│    - Deduplicate findings                                        │
│    - Returns: 8 findings (3 high, 5 medium)                      │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. Database Layer (store findings)                              │
│    - store_findings([8 findings])                                │
│    - Update scan status to 'completed'                           │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. CLI Layer (display results)                                  │
│    - Format output as table                                      │
│    - Display:                                                    │
│      ✓ Scan complete                                             │
│      Subdomains: 15                                              │
│      Open ports: 45                                              │
│      Findings: 8 (3 high, 5 medium)                              │
│                                                                  │
│      [Table showing findings with severity, risk score, etc.]    │
└──────────────────────────────────────────────────────────────────┘

Time: ~2-5 minutes (depending on domain size)
```

### 8.3 Finding Status Update Flow (PATCH)

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. HTTP Request                                                  │
│    PATCH /api/v1/findings/finding-123/status                     │
│    Headers: X-API-Key: <api-key>                                 │
│    Body: { "status": "resolved", "notes": "Fixed firewall" }     │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. API Layer - Authentication                                    │
│    - Extract X-API-Key header                                    │
│    - Verify API key (check hash in database)                     │
│    - Check permissions (finding:write)                           │
│    - Log to audit trail                                          │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. API Layer - Route Handler                                    │
│    - Validate request body (Pydantic)                            │
│    - Call AnalysisService                                        │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. Analysis Layer                                                │
│    - AlertManagementService.update_alert_status()                │
│    - Validate status transition (open → resolved)                │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. Database Layer                                                │
│    - Update findings table:                                      │
│      UPDATE findings                                             │
│      SET status = 'resolved',                                    │
│          resolved_at = NOW(),                                    │
│          resolution_notes = 'Fixed firewall',                    │
│          updated_at = NOW()                                      │
│      WHERE id = 'finding-123'                                    │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. HTTP Response                                                 │
│    200 OK                                                        │
│    { "success": true, "message": "Status updated" }              │
└──────────────────────────────────────────────────────────────────┘
```

---

## 9. Layer Interactions

### 8.1 Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│ Application Entry Points                                         │
│                                                                  │
│  ┌──────────────┐                    ┌──────────────┐          │
│  │  API Server  │                    │  CLI Script  │          │
│  │  (uvicorn)   │                    │ (openeasd.py)│          │
│  └───────┬──────┘                    └───────┬──────┘          │
└──────────┼─────────────────────────────────┼─────────────────────┘
           │                                  │
           │                                  │
┌──────────┼──────────────────────────────────┼─────────────────────┐
│          │         Layer 1 & 3              │                     │
│          │                                  │                     │
│          ▼                                  ▼                     │
│  ┌──────────────┐                  ┌──────────────┐             │
│  │  API Routes  │                  │ CLI Commands │             │
│  └──────┬───────┘                  └───────┬──────┘             │
│         │                                   │                     │
│         │            Both delegate to      │                     │
│         └──────────────────┬───────────────┘                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Layer 2: Service Layer                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │DomainService │  │ ScanService  │  │AlertService  │         │
│  └──────┬───────┘  └───────┬──────┘  └──────┬───────┘         │
└─────────┼──────────────────┼─────────────────┼─────────────────┘
          │                  │                 │
          │                  │                 │
    ┌─────┴────┬─────────────┴───────┬─────────┴────┐
    │          │                     │              │
    ▼          ▼                     ▼              ▼
┌─────────┐ ┌────────┐ ┌──────────────────┐ ┌──────────────┐
│Layer 6: │ │Layer 5:│ │   Layer 4:       │ │  Layer 6:    │
│Database │ │Tools   │ │   Analysis       │ │  Database    │
│         │ │        │ │                  │ │              │
│CRUD Ops │ │Subfind-│ │ - RiskScorer     │ │Store Results │
│         │ │er,Naabu│ │ - Detectors      │ │              │
│         │ │Dnsx,   │ │ - Finding Models │ │              │
│         │ │Httpx   │ │                  │ │              │
└─────────┘ └────────┘ └──────────────────┘ └──────────────┘
```

### 8.2 Layer Communication Patterns

#### Pattern 1: API → Service → Database
```
API Layer never talks directly to Database or Tools.
Always goes through Service Layer.

Example:
  GET /domains → DomainService.list_domains() → db.get_domains()
```

#### Pattern 2: CLI → Service → Tools → Database
```
CLI can call Service Layer which orchestrates Tools and Database.

Example:
  openeasd scan → ScanService.execute_scan()
               → run_subfinder() (Tools)
               → db.store_results() (Database)
```

#### Pattern 3: Service → Analysis → Database
```
After scan completion, Service Layer triggers Analysis Layer.
Analysis Layer runs detectors and stores findings.

Example:
  ScanService.execute_scan()
    → AnalysisService.analyze_scan()
      → PortDetector.analyze()
      → RiskScorer.score_finding()
      → db.store_findings()
```

#### Pattern 4: CLI → Tools (Direct)
```
CLI has special direct tool execution commands.
Bypasses Service Layer for raw tool access.

Example:
  openeasd run subfinder example.com → run_subfinder() directly
```

### 8.3 Interface Boundaries

#### Service Layer → Database Interface
```python
# Defined in src/core/interfaces/database.py
class DatabaseManager(ABC):
    @abstractmethod
    def create_scan_session(self, domain: str) -> ScanSession: pass

    @abstractmethod
    def store_findings(self, findings: List[Dict]) -> None: pass

    @abstractmethod
    def get_scan_results(self, scan_id: str) -> Dict: pass
```

#### API Layer → Service Interface
```python
# Dependency injection pattern
def get_domain_service(db: SQLModelManager = Depends(get_db_manager)):
    return DomainService(db)

# Usage in routes
@router.get("/domains")
async def list_domains(service: DomainService = Depends(get_domain_service)):
    return service.list_domains()
```

#### Service Layer → Tools Interface
```python
# Simple function calls, no formal interface
from src.tools.runners import run_subfinder, run_naabu

subdomains = run_subfinder(domain)  # Returns List[str]
ports = run_naabu(subdomains)       # Returns List[Dict]
```

---

## 10. Security Model

### 12.1 Two-Tier Access Model

OpenEASD implements a **security-first architecture** with two distinct access tiers:

#### Tier 1: Read-Only API (Port 8000)
**Purpose**: Safe remote monitoring and dashboards

**Access Control**:
- GET requests only (read-only)
- 1 PATCH endpoint (with API key authentication)
- No domain creation/deletion
- No scan execution
- Rate limited per API key

**Use Cases**:
- Remote monitoring dashboards
- Third-party SIEM integrations
- Status checks and reporting
- Finding status updates (with auth)

**Security Features**:
- API keys with SHA-256 hashing
- Rate limiting (50 ops/hour per key)
- Revocable keys
- Audit logging for PATCH operations
- CORS configuration

#### Tier 2: Full-Access CLI (Local)
**Purpose**: Complete operational control

**Access Control**:
- Local/SSH access required (physical security)
- Full CRUD operations
- Scan execution
- Direct tool access
- No rate limiting

**Use Cases**:
- Domain management (add/update/remove)
- Scan execution (single or batch)
- Analysis commands
- API key management
- Administrative operations

### 12.2 API Key Management

#### Key Generation
```bash
# Create API key with full permissions
$ openeasd apikey create --name "my-integration" --permissions "*"

Generated API Key: oeasd_aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY
⚠️  Store this key securely - it won't be shown again!

Key ID: key-123
Name: my-integration
Permissions: * (all)
Created: 2025-11-26 10:30:00 IST
```

#### Key Storage
- Plain key shown ONCE during creation
- SHA-256 hash stored in database (never plain text)
- Key format: `oeasd_` + 32 random characters
- Hash function: `SHA-256(plain_key)`

#### Key Verification
```python
# API middleware verifies on each request
api_key = request.headers.get("X-API-Key")
key_hash = hashlib.sha256(api_key.encode()).hexdigest()
stored_key = db.get_api_key_by_hash(key_hash)

if not stored_key or not stored_key.is_active:
    raise HTTPException(401, "Invalid or revoked key")
```

#### Key Permissions
```json
{
  "*": "All permissions (full access)",
  "domain:read": "List and view domains",
  "domain:write": "Create/update/delete domains",
  "scan:execute": "Execute scans",
  "finding:write": "Update finding status"
}
```

### 12.3 Rate Limiting

**Per API Key Limits**:
- Domain operations: 50 requests/hour
- Scan execution: 10 scans/hour
- Finding updates: 100 updates/hour
- Alert queries: 200 requests/hour

**Implementation**:
```python
# Rate limit middleware (pseudo-code)
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    api_key_id = await verify_api_key(request)

    # Check rate limit
    usage = redis.get(f"ratelimit:{api_key_id}:{endpoint}")
    if usage > limit:
        raise HTTPException(429, "Rate limit exceeded")

    # Increment counter
    redis.incr(f"ratelimit:{api_key_id}:{endpoint}", ex=3600)

    return await call_next(request)
```

### 12.4 Audit Logging

**All write operations are logged**:
- Domain creation/update/deletion
- Finding status changes
- API key creation/revocation

**Audit Log Schema**:
```python
class AuditLog(SQLModel, table=True):
    id: str  # UUID
    operation: str  # CREATE, UPDATE, DELETE
    entity_type: str  # domain, finding, api_key
    entity_id: str
    api_key_id: str
    changes_json: str  # Before/after values
    timestamp: datetime
    ip_address: str
```

**Example Audit Entry**:
```json
{
  "id": "audit-789",
  "operation": "UPDATE",
  "entity_type": "finding",
  "entity_id": "finding-123",
  "api_key_id": "key-456",
  "changes": {
    "status": {"old": "open", "new": "resolved"},
    "resolution_notes": {"old": null, "new": "Fixed firewall"}
  },
  "timestamp": "2025-11-26T10:45:00+05:30",
  "ip_address": "192.168.1.100"
}
```

---

## 11. File Reference by Layer

### Layer 1: API Layer
```
src/api/
├── main.py (111 lines)
│   └── FastAPI app, middleware, router registration
├── dependencies.py (145 lines)
│   └── Dependency injection (DB, services, auth)
├── middleware/
│   ├── auth.py
│   ├── rate_limit.py
│   └── audit.py
├── routes/
│   ├── __init__.py
│   ├── health.py (38 lines)
│   ├── domains.py (200+ lines)
│   ├── scans.py (200+ lines)
│   ├── alerts.py (100+ lines)
│   └── findings.py (260 lines)
└── schemas/
    ├── __init__.py
    ├── domain.py (104 lines)
    ├── scan.py (100+ lines)
    ├── alert.py (91 lines)
    ├── finding.py (88 lines)
    └── common.py
```

### Layer 2: Service Layer
```
src/services/
├── __init__.py
├── domain_service.py (200+ lines)
│   └── Domain CRUD business logic
├── scan_service.py (550+ lines)
│   └── Scan orchestration and workflow
└── alert_service.py (117 lines)
    └── Alert management (delegates to Analysis)
```

### Layer 3: CLI Layer
```
src/cli/
├── main.py (670+ lines)
│   └── Click CLI entry point, command groups
├── commands_scan.py (500+ lines)
│   └── Scan execution commands
├── commands_domain.py (200+ lines)
│   └── Domain management commands
├── commands_analysis.py (450+ lines)
│   └── Analysis and findings commands
├── commands_apikey.py (300+ lines)
│   └── API key management
├── commands_results.py
├── commands_subfinder.py
├── commands_naabu.py
├── commands_dnsx.py
├── commands_httpx.py
└── formatters.py (500+ lines)
    └── Output formatting (table, JSON, CSV, txt)
```

### Layer 4: Analysis Layer
```
src/analysis/
├── __init__.py
├── analysis_service.py (350+ lines)
│   └── Analysis orchestration
├── alert_service.py (400+ lines)
│   └── Alert management service
├── config.py
├── models.py (150+ lines)
│   └── Finding, Vulnerability, CVE models
├── scoring/
│   ├── __init__.py
│   └── risk_scorer.py (250+ lines)
│       └── 0-100 risk scoring algorithm
└── detectors/
    ├── __init__.py
    ├── base_detector.py (50+ lines)
    │   └── Abstract detector pattern
    └── port_detector.py (250+ lines)
        └── Port vulnerability detection
```

### Layer 5: Tools Layer
```
src/tools/
├── __init__.py
├── runners.py (250+ lines)
│   └── Main tool runner functions
├── subfinder/
│   └── __init__.py
├── naabu/
│   └── __init__.py
├── dnsx/
│   └── __init__.py
├── httpx/
│   └── __init__.py
├── amass/
│   └── __init__.py
└── nmap/
    └── __init__.py
```

### Layer 6: Database Layer
```
src/data/
├── database/
│   └── sqlmodel_manager.py (1500+ lines)
│       └── Complete database manager
└── models/
    ├── __init__.py
    ├── domain.py (50+ lines)
    ├── scan.py (50+ lines)
    ├── subdomain.py (50+ lines)
    ├── tool_results.py (150+ lines)
    ├── api_key.py (50+ lines)
    └── audit_log.py (50+ lines)
```

### Utilities and Core
```
src/
├── core/
│   └── interfaces/
│       └── database.py
│           └── DatabaseManager abstract interface
└── utils/
    ├── config.py
    │   └── Configuration management
    ├── timezone.py
    │   └── IST timezone utilities
    ├── validation.py
    │   └── Domain/input validation
    └── logging.py
        └── Logging configuration
```

---

## 12. Best Practices

### 12.1 When to Use Which Layer

#### Use API Layer When:
- Building a web dashboard or frontend
- Integrating with third-party monitoring tools
- Need remote read-only access
- Displaying real-time status information
- **Don't use for**: Domain management, scan execution

#### Use CLI Layer When:
- Managing domains (add/update/remove)
- Executing scans (single or batch)
- Administrative operations
- Direct tool execution needed
- Running from cron jobs or scripts

#### Use Service Layer When:
- Implementing new business logic
- Need to share logic between API and CLI
- Orchestrating multiple operations
- Enforcing business rules

#### Use Analysis Layer When:
- Adding new vulnerability detectors
- Customizing risk scoring
- Implementing CVE enrichment
- Creating custom alert logic

#### Use Tools Layer When:
- Integrating new security tools
- Need direct tool execution
- Parsing tool-specific output

#### Use Database Layer When:
- Creating new database tables
- Implementing complex queries
- Adding indexes for performance
- Managing relationships

### 12.2 Extension Patterns

#### Adding a New Detector
```python
# 1. Create detector class
from src.analysis.detectors.base_detector import BaseDetector

class MyCustomDetector(BaseDetector):
    def get_name(self) -> str:
        return "MyCustomDetector"

    def analyze(self, scan_data: Dict) -> List[Dict]:
        findings = []
        # Detection logic here
        return findings

# 2. Register in analysis_service.py
def _load_detectors(self):
    detectors = []
    detectors.append(PortVulnerabilityDetector())
    detectors.append(MyCustomDetector())  # Add here
    return detectors
```

#### Adding a New API Endpoint
```python
# 1. Create Pydantic schema in src/api/schemas/
class MyResponse(BaseModel):
    data: str

# 2. Add route in src/api/routes/
@router.get("/my-endpoint", response_model=MyResponse)
async def my_endpoint(service: MyService = Depends(get_my_service)):
    return service.get_data()

# 3. Register router in src/api/main.py
app.include_router(my_router, prefix="/api/v1/my")
```

#### Adding a New CLI Command
```python
# 1. Create command in src/cli/main.py
@click.group(name='mycommand')
def my_command_group():
    """My custom commands."""
    pass

@my_command_group.command('action')
@click.argument('arg')
def my_action(arg):
    """Execute my action."""
    # Implementation here

# 2. Register in CLI
cli.add_command(my_command_group)
```

### 12.3 Common Patterns

#### Pattern: Service Initialization with Dependency Injection
```python
class MyService:
    def __init__(self, db_manager: SQLModelManager):
        self.db = db_manager

    def do_something(self):
        # Use self.db for database operations
        pass
```

#### Pattern: Error Handling in Layers
```python
# Service Layer
def my_service_method(self):
    try:
        result = self.db.query()
        return {'success': True, 'data': result}
    except ValueError as e:
        # Business logic error
        return {'success': False, 'error': str(e)}
    except Exception as e:
        # Unexpected error
        logger.error(f"Unexpected error: {e}")
        raise

# API Layer
@router.get("/endpoint")
async def endpoint(service: MyService = Depends(get_service)):
    try:
        result = service.my_service_method()
        if not result['success']:
            raise HTTPException(400, result['error'])
        return result
    except Exception as e:
        raise HTTPException(500, "Internal server error")

# CLI Layer
@click.command()
def my_command():
    try:
        result = service.my_service_method()
        if result['success']:
            click.echo(click.style('✓ Success', fg='green'))
        else:
            click.echo(click.style(f'✗ Error: {result["error"]}', fg='red'))
    except Exception as e:
        click.echo(click.style(f'✗ Fatal error: {e}', fg='red'))
        sys.exit(1)
```

#### Pattern: Transaction Management
```python
# Always use context manager for database sessions
def my_database_operation(self):
    with Session(self.engine) as session:
        # All operations in transaction
        obj1 = MyModel(...)
        session.add(obj1)

        obj2 = RelatedModel(...)
        session.add(obj2)

        # Commit atomically
        session.commit()

        # Refresh to get updated values
        session.refresh(obj1)
        return obj1
```

### 12.4 Performance Tips

1. **Use Indexes**: Add indexes for frequently queried columns
2. **Batch Operations**: Use bulk inserts instead of loops
3. **Pagination**: Always limit query results
4. **Eager Loading**: Use joins to avoid N+1 queries
5. **Connection Pooling**: Reuse database connections
6. **Async Where Possible**: Use async/await in API layer
7. **Cache Results**: Cache frequently accessed data

### 12.5 Testing Guidelines

```python
# Test Service Layer (unit tests)
def test_domain_service_create():
    # Mock database
    mock_db = Mock(spec=SQLModelManager)
    service = DomainService(mock_db)

    # Test business logic
    result = service.create_domain('example.com')

    assert result['success'] == True
    mock_db.add_domain.assert_called_once()

# Test API Layer (integration tests)
from fastapi.testclient import TestClient

def test_api_list_domains():
    client = TestClient(app)
    response = client.get("/api/v1/domains")

    assert response.status_code == 200
    assert 'domains' in response.json()

# Test Database Layer (integration tests)
def test_database_create_scan():
    db = SQLModelManager(':memory:')  # In-memory DB
    db.initialize()

    scan = db.create_scan_session('example.com')

    assert scan.id is not None
    assert scan.domain == 'example.com'
```

---

## Summary

OpenEASD's **6-layer architecture** provides:

1. **Clear Separation**: Each layer has distinct responsibilities
2. **Security**: API read-only, CLI full-access
3. **Scalability**: Service layer shared between interfaces
4. **Extensibility**: Easy to add detectors, tools, endpoints
5. **Maintainability**: Well-organized codebase
6. **Production-Ready**: 79% test coverage, 97% tests passing

**Layer Summary**:
- **API**: Remote monitoring (GET only)
- **Service**: Business logic orchestration
- **CLI**: Full operational control
- **Analysis**: Vulnerability detection + risk scoring
- **Tools**: Security tool execution
- **Database**: Persistent storage (SQLite)

This architecture has been battle-tested with **367/378 passing tests** and is ready for production use.

---

**For Questions**: See `DESIGN.md`, `CLAUDE.md`, or `README.md`
**For Updates**: This document is version-controlled in the repository
