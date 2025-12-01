# CLAUDE.md - Project Guide for AI Assistants

**OpenEASD: Automated External Attack Surface Detection**

This project is organized across multiple documentation files. When assisting with this project, please refer to the appropriate document based on the context:

## Document Structure

### Business & Requirements
- **[REQUIREMENTS.md](./REQUIREMENTS.md)** - Business requirements and goals
  - Target audience: Product Managers, Stakeholders
  - Contains: Problem statement, functional requirements, performance targets

### Architecture Overview
- **[DESIGN.md](./DESIGN.md)** - System architecture overview
  - Target audience: System Architects, Technical Leads
  - Contains: 3-layer architecture diagram, technology stack, design principles

## Quick Reference

### Current Implementation Status
- **Architecture**: 7-layer design with Messaging, API, Analysis, and Real-time Events
- **Model**: Single-organization architecture (simplified from multi-org)
- **Tech Stack**: FastAPI (Read-Only), Click CLI (Full Access), ZeroMQ (Events), Python 3.11+, SQLite
- **Security Tools**: Subfinder, Amass, Nmap, Naabu (direct subprocess execution)
- **Analysis**: Automated vulnerability detection with risk scoring
- **Security Model**: API for monitoring (GET only), CLI for operations (full access)
- **Messaging**: Real-time event streaming with ZeroMQ Pub/Sub
- **Status**: Production-ready with API, CLI, Analysis, and Messaging Layer

### 7-Layer Architecture

1. **API Layer** ✅ - Read-only REST API (GET requests only) + WebSocket events
2. **Service Layer** ✅ - Business logic (used by both API and CLI)
3. **CLI Layer** ✅ - Full-featured command-line interface (read + write)
4. **Analysis Layer** ✅ - Automated vulnerability detection and risk scoring
5. **Tools Layer** ✅ - Security tool execution (Subfinder, Amass, Nmap, Naabu)
6. **Database Layer** ✅ - Data persistence and analytics (SQLite with SQLModel)
7. **Messaging Layer** ✅ - Real-time event streaming with ZeroMQ Pub/Sub

### Layer Responsibilities Quick Reference

**For comprehensive details, see [docs/LAYER_ARCHITECTURE.md](docs/LAYER_ARCHITECTURE.md)**

**Layer 1: API Layer** (`src/api/`)
- **What it does**: Provides read-only REST API for monitoring and dashboards
- **Key tasks**: HTTP request handling, API key authentication, rate limiting, CORS, OpenAPI docs
- **Access**: 24 GET endpoints + 1 PATCH endpoint (finding status updates)
- **Files**: `main.py`, `routes/*.py`, `schemas/*.py`, `dependencies.py`

**Layer 2: Service Layer** (`src/services/`)
- **What it does**: Shared business logic between API and CLI
- **Key tasks**: Domain CRUD, scan orchestration, alert management, analysis coordination
- **Services**: DomainService, ScanService, AlertService, AnalysisService
- **Files**: `domain_service.py`, `scan_service.py`, `alert_service.py`

**Layer 3: CLI Layer** (`src/cli/`)
- **What it does**: Full-access command-line interface for operations
- **Key tasks**: Command parsing, user interaction, output formatting, domain/scan/analysis commands
- **Output formats**: table, json, csv, txt
- **Files**: `main.py`, `commands_*.py`, `formatters.py`

**Layer 4: Analysis Layer** (`src/analysis/`)
- **What it does**: Automated vulnerability detection and risk assessment
- **Key tasks**: Risk scoring (0-100), port vulnerability detection, finding deduplication, CVE mapping
- **Components**: RiskScorer, PortVulnerabilityDetector, AlertManagementService
- **Files**: `analysis_service.py`, `scoring/risk_scorer.py`, `detectors/port_detector.py`, `models.py`

**Layer 5: Tools Layer** (`src/tools/`)
- **What it does**: Executes external security tools and parses results
- **Key tasks**: Subprocess execution, JSON parsing, timeout management, error handling
- **Tools**: Subfinder (subdomains), Naabu (ports), Dnsx (DNS), Httpx (HTTP probing)
- **Files**: `runners.py`, `subfinder/`, `naabu/`, `dnsx/`, `httpx/`

**Layer 6: Database Layer** (`src/data/`)
- **What it does**: Data persistence and query execution
- **Key tasks**: CRUD operations, relationship management, transactions, timezone conversion (IST)
- **Technology**: SQLite with SQLModel ORM, 15+ tables
- **Files**: `database/sqlmodel_manager.py`, `models/*.py`

**Layer 7: Messaging Layer** (`src/messaging/`) **NEW**
- **What it does**: Real-time event streaming and inter-layer communication
- **Key tasks**: Pub/Sub event distribution, WebSocket streaming, CLI progress display, event filtering
- **Components**: EventBus (ZeroMQ), EventPublisher, EventSubscriber, EventBusManager
- **Files**: `bus.py`, `publisher.py`, `subscriber.py`, `manager.py`, `events.py`
- **Features**: Topic-based filtering, non-blocking delivery, WebSocket support, 26+ tests

## Implementation Progress

| Layer | Status | Progress | Test Coverage | Notes |
|-------|--------|----------|--------|-------|
| API Layer | ✅ Complete | 100% | 77% | Read-only FastAPI, 24 endpoints, Pydantic schemas, WebSocket events |
| Service Layer | ✅ Complete | 100% | 85% | Domain, Scan, Alert, Analysis services |
| CLI Layer | ✅ Complete | 100% | 92% | Domain, scan, and analysis commands, real-time progress |
| Analysis Layer | ✅ Complete | 100% | 95% | Risk scoring, vulnerability detection, 56+ unit tests |
| Tools Layer | ✅ Complete | 100% | 93% | Direct subprocess calls, JSON parsing |
| Database Layer | ✅ Complete | 100% | 77% | SQLModel with findings, vulnerabilities, CVE mappings |
| Messaging Layer | ✅ Complete | 100% | 100% | ZeroMQ Pub/Sub, WebSocket, 26+ tests, real-time events |

## Test Suite Status

**Overall Coverage**: 79% (2,928/3,696 statements)
- **Total Tests**: 378
- **Passing Tests**: 367 ✅
- **Failing Tests**: 11 ⚠️
- **Test Files**: 19 modules

**Recent Improvements**:
- Fixed 10 tests with JSON formatting, mock setup, and test data issues
- Achieved 95% coverage on Analysis Layer (56+ tests)
- 367/378 tests passing (97.1% success rate)
- See [TEST_COVERAGE_REPORT.md](docs/TEST_COVERAGE_REPORT.md) for detailed breakdown

## Security Model: Read-Only API + Full-Access CLI

**Critical Design Decision**: Separation of monitoring and operations for enhanced security.

### API (Read-Only - Port 8000)
**Purpose**: Monitoring, dashboards, reporting, integrations
**Access Level**: GET requests only (no write operations)
**Use Cases**:
- View domains and scan status
- Monitor scan results and subdomains
- Check security alerts
- Dashboard and reporting integrations
- Third-party monitoring tools

**Available Endpoints**:
```
GET /api/v1/health                          # Health check
GET /api/v1/domains                         # List domains
GET /api/v1/domains/{domain}                # Domain details
GET /api/v1/scans                           # List scans
GET /api/v1/scans/{scan_id}                 # Scan status
GET /api/v1/scans/{scan_id}/results         # Scan results
GET /api/v1/alerts                          # List alerts
GET /api/v1/alerts/statistics               # Alert statistics
GET /api/v1/findings                        # List findings (NEW)
GET /api/v1/findings/{finding_id}           # Finding details (NEW)
GET /api/v1/findings/statistics/summary     # Finding statistics (NEW)
GET /api/v1/findings/scan/{scan_id}         # Findings by scan (NEW)
GET /api/v1/findings/asset/{asset_name}     # Findings by asset (NEW)
PATCH /api/v1/findings/{finding_id}/status  # Update status (NEW)
```

### CLI (Full Access)
**Purpose**: Operations, configuration, scan execution
**Access Level**: Full read/write access
**Use Cases**:
- Add, update, remove domains
- Execute scans (single or batch)
- Manage scan configurations
- Administrative operations

**Available Commands**:
```bash
# Domain Management
openeasd domain add <domain> --primary --notes "..." --tags "..."
openeasd domain update <domain> --primary --notes "..." --tags "..."
openeasd domain remove <domain>
openeasd domain list [--primary]
openeasd domain show <domain>

# Scan Operations
openeasd scan domain <domain>    # Single domain scan
openeasd scan                    # Batch scan all domains
openeasd history                 # View scan history
openeasd scans                   # List all scans
openeasd results <scan-id>       # View scan results

# Analysis & Findings (NEW)
openeasd analysis run <scan-id>           # Run analysis manually
openeasd analysis findings                # List all findings
openeasd analysis findings --severity high # Filter by severity
openeasd analysis show <finding-id>       # Show finding details
openeasd analysis stats                   # View statistics
openeasd analysis update <id> resolved    # Update finding status

# Direct Tool Execution
openeasd run subfinder <domain>
openeasd run naabu <domain>
openeasd run dnsx <domain>
```

### Why This Model?

**Security Benefits**:
1. **Minimized Attack Surface**: API cannot be used to trigger scans or modify data
2. **Controlled Access**: Operations require local/SSH access to CLI
3. **Audit Trail**: All write operations go through CLI with proper logging
4. **Safe Integrations**: Third-party tools can monitor without risk of modifications
5. **Defense in Depth**: Even if API is compromised, no write operations possible

**Operational Benefits**:
1. **Dashboard Access**: Safe remote access for monitoring
2. **Team Collaboration**: Share read-only access with team members
3. **Integration Ready**: Connect monitoring tools, SIEMs, dashboards
4. **Separation of Concerns**: Clear boundary between monitoring and operations

## Key Implementation Notes

1. **6-layer architecture** with Read-Only API and Analysis Layer
2. **API for monitoring** (GET only), **CLI for operations** (full access)
3. **Analysis Layer** for automated vulnerability detection and risk scoring
4. **Service layer** shared between API and CLI for business logic
5. **Single organization** model (no multi-tenancy)
6. **Direct tool execution** via subprocess (no orchestration layer)
7. **Security tools** in `src/tools/{tool}/` modules
8. **SQLite with SQLModel** for ORM and database operations
9. **IST timezone** support for all timestamps
10. **FastAPI** with Pydantic v2 for API validation
11. **Dependency injection** for service management
12. **Deterministic risk scoring** (0-100 scale) with score breakdown

## Current Features

### ✅ Fully Implemented (All 6 Layers)

**API Layer (Read-Only)**:
- FastAPI application with OpenAPI/Swagger documentation
- 24 read-only endpoints (GET requests only) + 1 PATCH endpoint
- Health check endpoint
- Domain listing and details
- Scan status and results
- Security alerts and statistics
- **Findings management (7 new endpoints)**
- Pydantic v2 schemas for validation
- CORS middleware for cross-origin requests
- JSON responses with proper error handling
- Auto-generated API documentation at `/api/docs`

**Service Layer**:
- **DomainService**: Domain CRUD operations, validation
- **ScanService**: Scan creation, execution, status tracking, analysis integration
- **AlertService**: Alert retrieval, statistics, filtering
- **AnalysisService**: Vulnerability detection orchestration (NEW)
- Shared business logic between API and CLI
- Domain validation and duplicate checking
- Scan workflow orchestration
- Alert aggregation and analysis

**CLI Layer (Full Access)**:
- Scan commands: `scan domain`, `scan` (batch mode)
- Domain management: `add`, `list`, `update`, `remove`
- **Analysis commands: `run`, `findings`, `show`, `stats`, `update` (NEW)**
- History & results: `history`, `scans`, `results`
- Output formats: table, json, csv, txt
- Single-organization model (simplified)
- UUID-based scan tracking
- Batch scanning for multiple domains
- Interactive deletion with preview

**Analysis Layer (NEW)**:
- **RiskScorer**: Deterministic risk scoring (0-100 scale)
  - Base score (0-40): Inherent risk of finding type
  - Context score (0-40): Business context and asset criticality
  - Exposure score (0-20): Public accessibility
- **PortVulnerabilityDetector**: Port-based vulnerability detection
  - Database exposure detection (MySQL, PostgreSQL, MongoDB, Redis)
  - High-risk services (Telnet, FTP, RDP, VNC)
  - Admin interface detection
  - Remote access service detection
- **BaseDetector**: Abstract detector pattern for extensibility
- Automated finding deduplication
- CVE-ready database schema
- 56 unit tests + 15 integration tests

**Tools Layer**:
- **Subfinder**: Passive subdomain discovery (actively used)
- **Amass**: Comprehensive subdomain enumeration (module available)
- **Nmap**: Service detection and port scanning (module available)
- **Naabu**: Fast port scanning (actively used)
- Direct subprocess execution
- JSON output parsing

**Database Layer**:
- SQLite with SQLModel ORM
- Domain registry with metadata (notes, tags, scan frequency)
- Scan session tracking with status management
- Subdomain history tracking (new/existing/removed)
- Security alerts generation
- Tool-specific result tables
- **4 new analysis tables: findings, vulnerabilities, cve_mappings, finding_groups (NEW)**
- Timezone-aware timestamps (IST)
- Efficient JOINs and aggregations
- Single-organization model (no multi-tenancy)

## Data Flow

### 7-Layer Workflow (API Path - Read-Only with Real-time Events)

```
HTTP Request: GET /api/v1/domains
    ↓
┌──────────────────────────────┐
│ API Layer                    │
│ - FastAPI endpoint           │
│ - Validate request params    │
│ - Dependency injection       │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Service Layer                │
│ - DomainService.list_domains │
│ - Business logic             │
│ - Data formatting            │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Database Layer               │
│ - DuckDB query execution     │
│ - Fetch domain records       │
│ - Return results             │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Service Layer                │
│ - Format response data       │
│ - Apply business rules       │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ API Layer                    │
│ - Pydantic validation        │
│ - JSON serialization         │
│ - HTTP response              │
└──────────────────────────────┘
```

### 7-Layer Workflow (CLI Path - Full Access with Real-time Events)

```
User Command: openeasd scan domain example.com
    ↓
┌──────────────────────────────┐
│ CLI Layer                    │
│ - Parse & validate args      │
│ - Create scan session (UUID) │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Service Layer                │
│ - ScanService.execute_scan   │
│ - Orchestrate workflow       │
│ - Publish events via EventBus│
└──────────────────────────────┘
    ↓                       ↓ (events)
┌──────────────────────────────┐  ┌──────────────────────────────┐
│ Tools Layer                  │  │ Messaging Layer              │
│ - Execute subfinder          │  │ - EventBus (ZeroMQ)          │
│ - Execute dnsx               │  │ - Publish scan.started       │
│ - Execute naabu              │  │ - Publish tool.completed     │
│ - Parse JSON output          │  │ - Publish finding.discovered │
└──────────────────────────────┘  └──────────────────────────────┘
    ↓                                ↓ (subscribe)
┌──────────────────────────────┐  ┌──────────────────────────────┐
│ Database Layer               │  │ CLI Progress Display         │
│ - Store scan session         │  │ - EventSubscriber            │
│ - Store subfinder results    │  │ - Real-time progress         │
│ - Track subdomain changes    │  │ - Live finding alerts        │
│ - Generate security alerts   │  │ - Tool status updates        │
└──────────────────────────────┘  └──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ CLI Layer                    │
│ - Format output (table/json) │
│ - Display to user            │
└──────────────────────────────┘
```

## For AI Assistants

When helping with this project:

### General Guidelines
- **Follow DESIGN.md**: For overall architecture and system design principles
- **Respect layer boundaries**: Keep layer responsibilities clean and focused
- **Security Model**: API is read-only (GET only), CLI has full access
- **Service Layer**: Shared business logic between API and CLI
- **Single organization**: No multi-tenancy complexity
- **Direct tool execution**: Tools called via subprocess, no orchestration layer

### Current State Awareness
- **API Layer**: Production-ready with 24+ endpoints, FastAPI + Pydantic v2, WebSocket events
- **Service Layer**: Business logic shared between API and CLI
- **CLI Layer**: Production-ready with all commands implemented (full access), real-time progress
- **Analysis Layer**: Automated vulnerability detection, risk scoring (95% coverage)
- **Tools Layer**: Subfinder, Naabu, Dnsx, Httpx actively used
- **Database Layer**: SQLite with SQLModel fully implemented, single-org schema
- **Messaging Layer**: ZeroMQ Pub/Sub event bus, WebSocket streaming, 26+ tests

### File Organization
```
src/
├── api/              # Layer 1 ✅ - Read-only REST API + WebSocket
│   ├── main.py       # FastAPI application
│   ├── dependencies.py  # Dependency injection
│   ├── routes/       # API endpoints
│   │   ├── domains.py   # GET /api/v1/domains
│   │   ├── scans.py     # GET /api/v1/scans
│   │   ├── alerts.py    # GET /api/v1/alerts
│   │   ├── findings.py  # GET /api/v1/findings (7 endpoints)
│   │   ├── events.py    # WebSocket /api/v1/events
│   │   └── health.py    # GET /api/v1/health
│   └── schemas/      # Pydantic models
│       ├── domain.py
│       ├── scan.py
│       └── alert.py
├── services/         # Layer 2 ✅ - Business logic
│   ├── domain_service.py   # Domain operations
│   ├── scan_service.py     # Scan orchestration
│   └── alert_service.py    # Alert management
├── cli/              # Layer 3 ✅ - Full-access CLI
│   ├── main.py
│   ├── commands_scan.py
│   ├── commands_domain.py
│   ├── commands_analysis.py
│   ├── progress.py        # Real-time progress display
│   └── formatters.py
├── analysis/         # Layer 4 ✅ - Vulnerability detection
│   ├── analysis_service.py
│   ├── scoring/
│   │   └── risk_scorer.py
│   └── detectors/
│       └── port_detector.py
├── tools/            # Layer 5 ✅ - Security tool modules
│   ├── subfinder/
│   ├── amass/
│   ├── nmap/
│   ├── naabu/
│   ├── dnsx/
│   └── httpx/
├── data/             # Layer 6 ✅ - SQLite + SQLModel
│   ├── database/
│   │   └── sqlmodel_manager.py
│   └── models/
├── messaging/        # Layer 7 ✅ - ZeroMQ event bus
│   ├── bus.py
│   ├── publisher.py
│   ├── subscriber.py
│   ├── manager.py
│   └── events.py
├── core/             # Core infrastructure
└── utils/            # Utilities (config, logging, timezone, validation)
```

### Common Tasks

**Adding a new API endpoint** (Read-Only):
1. Define Pydantic schema in `src/api/schemas/`
2. Add service method in appropriate service (e.g., `src/services/domain_service.py`)
3. Create GET endpoint in `src/api/routes/`
4. Add route to `src/api/main.py`
5. Test with `curl` or browser at `http://localhost:8000/api/docs`
6. **Remember**: API is read-only, only add GET endpoints

**Adding a new CLI command**:
1. Add Click command in `src/cli/main.py`
2. Implement logic in `src/cli/commands.py` or `commands_domain.py`
3. Add formatter support in `src/cli/formatters.py`
4. Can use service layer methods if needed
5. Update DESIGN.md documentation

**Adding a new security tool**:
1. Create `src/tools/{tool}/` directory
2. Add `__init__.py` and `runner.py`
3. Implement subprocess execution and JSON parsing
4. Add CLI command in `src/cli/commands.py`
5. Optionally add service method for orchestration
6. Test tool execution and data storage

**Database schema changes**:
1. Review `src/data/database/duckdb_manager.py`
2. Update table creation in `_initialize_sync()`
3. Test schema changes carefully
4. Update service layer if needed
5. Update DESIGN.md with schema documentation
6. **Note**: Avoid adding indexes on scan_sessions (DuckDB limitation)

## Technology Stack

### All Layers (Fully Implemented)
- **API**: FastAPI 0.109+, Uvicorn, Pydantic v2, Python 3.11+, WebSocket
- **Services**: Business logic, dependency injection
- **CLI**: Click 8.1.7, Python 3.11+, real-time progress display
- **Analysis**: Risk scoring, vulnerability detection, finding management
- **Tools**: Subprocess execution, JSON parsing, Asyncio
- **Database**: SQLite with SQLModel ORM, 15+ tables
- **Messaging**: ZeroMQ 27.1.0+ (PyZMQ), Pub/Sub pattern, IPC transport

### Security Tool Dependencies
- **Subfinder**: https://github.com/projectdiscovery/subfinder (actively used)
- **Amass**: https://github.com/owasp-amass/amass (module available)
- **Nmap**: https://nmap.org/ (module available)
- **Naabu**: https://github.com/projectdiscovery/naabu (module available)

### Python Dependencies
- **Package Manager**: uv (fast Python package installer)
- **API Framework**: FastAPI 0.109+ - Modern async web framework
- **Validation**: Pydantic 2.5+ - Data validation with type hints
- **Server**: Uvicorn 0.27+ - ASGI server with uvloop
- **HTTP Client**: HTTPX 0.26+ - Async HTTP client
- **CLI Framework**: Click 8.1.7 - Command-line interface
- **Database**: SQLModel with SQLite - ORM and embedded database
- **Messaging**: PyZMQ 27.1.0+ - Python bindings for ZeroMQ
- **Timezone**: pytz - IST timezone support
- **Config**: PyYAML 6.0.1 - Configuration files
- **Testing**: pytest 8.2.2 - Testing framework (dev dependency)

## Testing

### Run Tests

```bash
# Run all tests with coverage
uv run pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_risk_scorer.py -v

# Run tests matching pattern
uv run pytest tests/ -k "test_domain" -v

# Run with HTML coverage report
uv run pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html in browser
```

### Test Quality

- **367/378 tests passing** (97.1% success rate)
- **79% code coverage** with 2,928 statements covered
- **Excellent coverage**: Analysis (95%), CLI (92%), Tools (93%)
- **Good coverage**: Services (85%), API (77%), Database (77%)
- **19 test modules** covering all major functionality
- **56+ unit tests** for risk scoring and vulnerability detection

### Areas for Test Improvement

- API findings routes (32% coverage)
- CLI main module (47% coverage)
- API key management (23% coverage)
- Tool modules (0% coverage - need integration tests)

See [TEST_COVERAGE_REPORT.md](docs/TEST_COVERAGE_REPORT.md) for detailed test statistics and improvement roadmap.

## Best Practices

1. **Security First**: API is read-only (GET only), CLI has full access
2. **Layer Separation**: Respect boundaries between API, Service, CLI, Tools, Database
3. **Service Layer**: Share business logic between API and CLI via services
4. **Single Organization**: No multi-tenancy complexity
5. **Direct Execution**: Call tools via subprocess, no orchestration layer
6. **Error Handling**: Use proper try/except and logging
7. **Async Patterns**: Use `async/await` for database operations
8. **IST Timezone**: All timestamps in Indian Standard Time
9. **Pydantic Validation**: Use Pydantic v2 for API request/response validation
10. **Test Coverage**: Aim for 85%+ coverage on new code
11. **Mock External Services**: Use pytest fixtures for database and service mocking

## Quick Start for Development

### Setup
```bash
# Install dependencies using uv
uv sync
```

### Running the API Server (Read-Only)
```bash
# Start the API server
uv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Access the API documentation
# Open browser: http://localhost:8000/api/docs

# Test API endpoints
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/domains
curl http://localhost:8000/api/v1/scans
```

### Using the CLI (Full Access)

#### Domain Management (CLI Only)
```bash
# Add a domain
uv run python openeasd.py domain add example.com --primary --notes "Production domain"

# Update domain
uv run python openeasd.py domain update example.com --primary true

# View domain list
uv run python openeasd.py domain list

# Remove a domain
uv run python openeasd.py domain remove example.com
```

#### Scan Operations (CLI Only)
```bash
# Run a single domain scan
uv run python openeasd.py scan domain example.com

# Run batch scan (all domains)
uv run python openeasd.py scan

# Run batch scan (primary domains only)
uv run python openeasd.py scan --primary-only
```

#### Viewing Results (CLI or API)
```bash
# CLI: View scan history
uv run python openeasd.py history

# CLI: View all scans
uv run python openeasd.py scans

# CLI: View specific scan results
uv run python openeasd.py results <scan-id>

# API: Same data via HTTP
curl http://localhost:8000/api/v1/scans
curl http://localhost:8000/api/v1/scans/<scan-id>
curl http://localhost:8000/api/v1/scans/<scan-id>/results
```

#### API Key Management (NEW - Write Operations with Authentication)

**Note**: The API now supports write operations (domain creation/update/deletion, scan execution) with API key-based authentication.

##### Creating API Keys

```bash
# Create a new API key with all permissions
uv run python openeasd.py apikey create --name "my-integration" --permissions "*"

# Create a domain-write only API key
uv run python openeasd.py apikey create --name "domain-writer" --permissions "domain:write"

# Create a scan-execute only API key
uv run python openeasd.py apikey create --name "scan-executor" --permissions "scan:execute"

# List all API keys
uv run python openeasd.py apikey list

# Revoke an API key by ID
uv run python openeasd.py apikey revoke <key-id>
```

**Important**: The plain API key is displayed ONLY once during creation. Store it securely. If lost, create a new key.

##### Using API Keys with Write Operations

```bash
# Create a domain via API
curl -X POST http://localhost:8000/api/v1/domains \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_primary": true}'

# Update a domain
curl -X PATCH http://localhost:8000/api/v1/domains/example.com \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"is_primary": false}'

# Delete a domain
curl -X DELETE "http://localhost:8000/api/v1/domains/example.com?force=true" \
  -H "X-API-Key: your-api-key-here"

# Execute a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Trigger analysis on completed scan
curl -X POST http://localhost:8000/api/v1/scans/<scan-id>/analysis \
  -H "X-API-Key: your-api-key-here"
```

**Permission Levels**:
- `"*"` (all permissions) - Full access to all operations
- `"domain:write"` - Create, update, delete domains
- `"scan:execute"` - Execute scans and trigger analysis

**Security Features**:
- API keys are SHA-256 hashed in the database (never stored in plain text)
- All write operations are logged to audit trail
- Rate limiting: 50 domain operations/hour, 10 scans/hour per API key
- Revoked keys are immediately rejected
- API keys are case-sensitive and whitespace-sensitive

## Architecture Evolution

### Version History
- **v10.0** (December 2025): **7-layer with Messaging Layer** - real-time event streaming with ZeroMQ
- **v9.0** (December 2025): 6-layer with Analysis Layer - automated vulnerability detection and risk scoring
- **v8.0** (November 2025): 5-layer with Read-Only API, API + Service + CLI + Tools + Database
- **v7.0** (November 2025): 3-layer architecture, single-organization, production-ready (CLI only)
- **v6.0** (October 2025): 5-layer architecture, 3 implemented + 2 planned (deprecated)
- **v5.0** (January 2025): 4-layer simplified design (deprecated)
- **Earlier**: 6-layer design with API/Scheduler (outdated)

### Current Focus
- ✅ Production-ready 7-layer architecture with Messaging and Analysis
- ✅ API for monitoring (GET only), CLI for operations (full access)
- ✅ **Real-time event streaming with ZeroMQ Pub/Sub (NEW)**
- ✅ **WebSocket API for live scan progress (NEW)**
- ✅ **CLI real-time progress display (NEW)**
- ✅ Automated vulnerability detection and risk scoring
- ✅ Service layer for shared business logic
- ✅ Single-organization model (simplified from multi-org)
- ✅ All core features implemented and tested (400+ tests total)
- ✅ FastAPI with Pydantic v2 validation and WebSocket support
- ✅ Direct subprocess tool execution
- ✅ SQLite with SQLModel ORM
- ✅ ZeroMQ event bus with topic-based filtering

---

*This guide helps AI assistants understand the project structure. For detailed information, refer to DESIGN.md.*

**Last Updated**: December 1, 2025
**Architecture Version**: 7-Layer (Messaging + Analysis + Read-Only API + Full-Access CLI)
**Package Manager**: uv (migrated from pip)
**Security Model**: API (read-only) + CLI (full access)
**Messaging**: ZeroMQ Pub/Sub event bus + WebSocket streaming
**Analysis**: Deterministic risk scoring (0-100) + vulnerability detection
**Test Coverage**: 79% (2,928/3,696 statements) - 367/378 tests passing + 26 messaging tests
**Status**: Production-ready with real-time events, comprehensive test coverage, and analysis layer

### Running Commands

#### API Server (Read-Only)
```bash
# Start API server with auto-reload
uv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# API Documentation
http://localhost:8000/api/docs
```

#### CLI (Full Access)
```bash
# With uv
uv run python openeasd.py <command>

# Direct python
/Users/rathnakara/projects/OpenEASD/.venv/bin/python openeasd.py <command>

# With venv activated
source .venv/bin/activate
python openeasd.py <command>
```
- you alway run uv run python when you want run python