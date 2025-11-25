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
- **Architecture**: 5-layer design with Read-Only API
- **Model**: Single-organization architecture (simplified from multi-org)
- **Tech Stack**: FastAPI (Read-Only), Click CLI (Full Access), Python 3.11+, DuckDB
- **Security Tools**: Subfinder, Amass, Nmap, Naabu (direct subprocess execution)
- **Security Model**: API for monitoring (GET only), CLI for operations (full access)
- **Status**: Production-ready with API and CLI interfaces

### 5-Layer Architecture

1. **API Layer** ✅ - Read-only REST API (GET requests only)
2. **Service Layer** ✅ - Business logic (used by both API and CLI)
3. **CLI Layer** ✅ - Full-featured command-line interface (read + write)
4. **Tools Layer** ✅ - Security tool execution (Subfinder, Amass, Nmap, Naabu)
5. **Database Layer** ✅ - Data persistence and analytics (DuckDB)

## Implementation Progress

| Layer | Status | Progress | Notes |
|-------|--------|----------|-------|
| API Layer | ✅ Complete | 100% | Read-only FastAPI, 17 endpoints, Pydantic schemas |
| Service Layer | ✅ Complete | 100% | Domain, Scan, Alert services with business logic |
| CLI Layer | ✅ Complete | 100% | Scan & domain commands, batch operations, full access |
| Tools Layer | ✅ Complete | 100% | Direct subprocess calls, JSON parsing |
| Database Layer | ✅ Complete | 100% | Single-org model, IST timezone support |

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
GET /api/v1/health              # Health check
GET /api/v1/domains             # List domains
GET /api/v1/domains/{domain}    # Domain details
GET /api/v1/scans               # List scans
GET /api/v1/scans/{scan_id}     # Scan status
GET /api/v1/scans/{scan_id}/results  # Scan results
GET /api/v1/alerts              # List alerts
GET /api/v1/alerts/statistics   # Alert statistics
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

1. **5-layer architecture** with Read-Only API security model
2. **API for monitoring** (GET only), **CLI for operations** (full access)
3. **Service layer** shared between API and CLI for business logic
4. **Single organization** model (no multi-tenancy)
5. **Direct tool execution** via subprocess (no orchestration layer)
6. **Security tools** in `src/tools/{tool}/` modules
7. **DuckDB analytics** for efficient querying and aggregations
8. **IST timezone** support for all timestamps
9. **FastAPI** with Pydantic v2 for API validation
10. **Dependency injection** for service management

## Current Features

### ✅ Fully Implemented (All 5 Layers)

**API Layer (Read-Only)**:
- FastAPI application with OpenAPI/Swagger documentation
- 17 read-only endpoints (GET requests only)
- Health check endpoint
- Domain listing and details
- Scan status and results
- Security alerts and statistics
- Pydantic v2 schemas for validation
- CORS middleware for cross-origin requests
- JSON responses with proper error handling
- Auto-generated API documentation at `/api/docs`

**Service Layer**:
- **DomainService**: Domain CRUD operations, validation
- **ScanService**: Scan creation, execution, status tracking
- **AlertService**: Alert retrieval, statistics, filtering
- Shared business logic between API and CLI
- Domain validation and duplicate checking
- Scan workflow orchestration
- Alert aggregation and analysis

**CLI Layer (Full Access)**:
- Scan commands: `scan domain`, `scan subfinder` (batch mode)
- Domain management: `add`, `list`, `update`, `remove`, `show`
- History & results: `history`, `scans`, `results`
- Output formats: table, json, csv, txt
- Single-organization model (simplified)
- UUID-based scan tracking
- Batch scanning for multiple domains
- Interactive deletion with preview

**Tools Layer**:
- **Subfinder**: Passive subdomain discovery (actively used)
- **Amass**: Comprehensive subdomain enumeration (module available)
- **Nmap**: Service detection and port scanning (module available)
- **Naabu**: Fast port scanning (module available)
- Direct subprocess execution
- JSON output parsing

**Database Layer**:
- DuckDB embedded database
- Domain registry with metadata (notes, tags, scan frequency)
- Scan session tracking with status management
- Subdomain history tracking (new/existing/removed)
- Security alerts generation
- Tool-specific result tables
- Timezone-aware timestamps (IST)
- Efficient JOINs and aggregations
- Single-organization model (no multi-tenancy)

## Data Flow

### 5-Layer Workflow (API Path - Read-Only)

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

### 5-Layer Workflow (CLI Path - Full Access)

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
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Tools Layer                  │
│ - Execute subfinder          │
│ - Execute dnsx               │
│ - Execute naabu              │
│ - Parse JSON output          │
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ Database Layer               │
│ - Store scan session         │
│ - Store subfinder results    │
│ - Track subdomain changes    │
│ - Generate security alerts   │
└──────────────────────────────┘
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
- **API Layer**: Production-ready with 17 read-only endpoints, FastAPI + Pydantic v2
- **Service Layer**: Business logic shared between API and CLI
- **CLI Layer**: Production-ready with all commands implemented (full access)
- **Tools Layer**: Subfinder actively used, other tools available as modules
- **Database Layer**: DuckDB fully implemented with single-org schema

### File Organization
```
src/
├── api/              # Layer 1 ✅ - Read-only REST API
│   ├── main.py       # FastAPI application
│   ├── dependencies.py  # Dependency injection
│   ├── routes/       # API endpoints
│   │   ├── domains.py   # GET /api/v1/domains
│   │   ├── scans.py     # GET /api/v1/scans
│   │   ├── alerts.py    # GET /api/v1/alerts
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
│   ├── commands.py
│   ├── commands_domain.py
│   └── formatters.py
├── tools/            # Layer 4 ✅ - Security tool modules
│   ├── subfinder/
│   ├── amass/
│   ├── nmap/
│   └── naabu/
├── data/             # Layer 5 ✅ - DuckDB manager
│   └── database/
│       └── duckdb_manager.py
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
- **API**: FastAPI 0.109+, Uvicorn, Pydantic v2, Python 3.11+
- **Services**: Business logic, dependency injection
- **CLI**: Click 8.1.7, Python 3.11+
- **Tools**: Subprocess execution, JSON parsing, Asyncio
- **Database**: DuckDB 1.4.1, SQL, Python asyncio wrapper

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
- **Database**: DuckDB 1.4.1 - Embedded analytical database
- **Timezone**: pytz - IST timezone support
- **Config**: PyYAML 6.0.1 - Configuration files
- **Testing**: pytest 8.2.2 - Testing framework (dev dependency)

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
10. **No scan_sessions indexes**: Avoid due to DuckDB UPDATE limitation

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

## Architecture Evolution

### Version History
- **v8.0** (November 2025): 5-layer with Read-Only API, API + Service + CLI + Tools + Database
- **v7.0** (November 2025): 3-layer architecture, single-organization, production-ready (CLI only)
- **v6.0** (October 2025): 5-layer architecture, 3 implemented + 2 planned (deprecated)
- **v5.0** (January 2025): 4-layer simplified design (deprecated)
- **Earlier**: 6-layer design with API/Scheduler (outdated)

### Current Focus
- ✅ Production-ready 5-layer architecture with Read-Only API
- ✅ API for monitoring (GET only), CLI for operations (full access)
- ✅ Service layer for shared business logic
- ✅ Single-organization model (simplified from multi-org)
- ✅ All core features implemented and tested
- ✅ FastAPI with Pydantic v2 validation
- ✅ Direct subprocess tool execution
- ✅ DuckDB with optimized queries

---

*This guide helps AI assistants understand the project structure. For detailed information, refer to DESIGN.md.*

**Last Updated**: November 2025
**Architecture Version**: 5-Layer (Read-Only API + Full-Access CLI)
**Package Manager**: uv (migrated from pip)
**Security Model**: API (read-only) + CLI (full access)

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