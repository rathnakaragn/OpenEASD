# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (6-Layer Design)
**Version**: 9.0 - Production-Ready with Analysis Layer
**Last Updated**: December 2025
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Architecture Overview

OpenEASD implements automated external attack surface detection through a streamlined 6-layer architecture with read-only API monitoring and full-access CLI operations.

### System Architecture (6-Layer Design)

```
┌─────────────────────────────────────────────────────────────┐
│              OpenEASD - 6-Layer Architecture                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: API Layer (Read-Only Monitoring) ✅               │
│    • FastAPI REST endpoints (GET only)                     │
│    • Pydantic v2 validation                                │
│    • CORS middleware                                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Service Layer (Business Logic) ✅                 │
│    • DomainService, ScanService, AlertService              │
│    • AnalysisService, FindingsService                      │
│    • Shared between API and CLI                            │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: CLI Layer (Full Access Operations) ✅             │
│    • Domain management: add | list | update | remove       │
│    • Scan operations: scan domain | scan                   │
│    • Analysis: findings | stats | run                      │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Analysis Layer (Vulnerability Detection) ✅       │
│    • RiskScorer (0-100 deterministic scoring)              │
│    • PortVulnerabilityDetector                             │
│    • Finding deduplication and CVE mapping                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Tools Layer (Security Tools) ✅                   │
│    • Subfinder - Passive subdomain discovery               │
│    • Naabu - Fast port scanning                            │
│    • Dnsx - DNS resolution                                 │
│    • Httpx - HTTP probing                                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Database Layer (Storage) ✅                       │
│    • SQLite with SQLModel ORM                              │
│    • 15+ tables for domains, scans, findings               │
│    • Timezone-aware timestamps (IST)                       │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Status

| Layer | Status | Components | Notes |
|-------|--------|------------|-------|
| **Layer 1: API** | ✅ Complete | FastAPI, Pydantic v2 | Read-only GET endpoints |
| **Layer 2: Service** | ✅ Complete | 5 services | Shared business logic |
| **Layer 3: CLI** | ✅ Complete | Click commands | Full access operations |
| **Layer 4: Analysis** | ✅ Complete | RiskScorer, Detectors | 95% test coverage |
| **Layer 5: Tools** | ✅ Complete | 4 security tools | Direct subprocess |
| **Layer 6: Database** | ✅ Complete | SQLite + SQLModel | Single-org model |

---

## Security Model

### Read-Only API + Full-Access CLI

**Critical Design Decision**: Separation of monitoring and operations for enhanced security.

**API Layer (Port 8000)**:
- GET requests only (no write operations)
- Safe for dashboards, monitoring, integrations
- No authentication required for read access

**CLI Layer**:
- Full read/write access
- Requires local/SSH access
- All modifications go through CLI

---

## Layer Details

### Layer 1: API Layer

**Purpose**: Read-only monitoring and dashboard integration
**Technology**: FastAPI 0.109+, Pydantic v2, Uvicorn

**Endpoints**:
```
GET /api/v1/health                     # Health check
GET /api/v1/domains                    # List domains
GET /api/v1/domains/{domain}           # Domain details
GET /api/v1/scans                      # List scans
GET /api/v1/scans/{scan_id}            # Scan status
GET /api/v1/scans/{scan_id}/results    # Scan results
GET /api/v1/alerts                     # List alerts
GET /api/v1/findings                   # List findings
GET /api/v1/findings/{id}              # Finding details
GET /api/v1/findings/statistics/summary # Statistics
```

### Layer 2: Service Layer

**Purpose**: Shared business logic between API and CLI
**Services**:
- **DomainService**: Domain CRUD operations
- **ScanService**: Scan execution and tracking
- **AlertService**: Security alert management
- **AnalysisService**: Vulnerability detection orchestration
- **FindingsService**: Finding retrieval and statistics

### Layer 3: CLI Layer

**Purpose**: Full-access command-line operations
**Technology**: Click 8.1.7

**Commands**:
```bash
# Domain Management
openeasd domain add <domain> --primary
openeasd domain list [--primary]
openeasd domain update <domain> --primary true
openeasd domain remove <domain> --force

# Scan Operations
openeasd scan domain <domain>          # Single domain
openeasd scan [--primary]              # Batch scan

# Results
openeasd scans                         # List scans
openeasd results <scan-id>             # View results

# Analysis
openeasd analysis findings             # List findings
openeasd analysis stats                # Statistics
openeasd analysis run <scan-id>        # Run analysis
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

### Layer 6: Database Layer

**Purpose**: Data persistence with SQLModel ORM
**Technology**: SQLite, SQLModel, Python 3.11+

**Core Tables**:
- domains, scan_sessions, subdomain_history
- security_alerts, findings, vulnerabilities
- cve_mappings, finding_groups

---

## Project Structure

```
OpenEASD/
├── src/
│   ├── api/                  # Layer 1: API
│   │   ├── main.py
│   │   ├── routes/
│   │   └── schemas/
│   ├── services/             # Layer 2: Services
│   │   ├── domain_service.py
│   │   ├── scan_service.py
│   │   └── findings_service.py
│   ├── cli/                  # Layer 3: CLI
│   │   ├── main.py
│   │   ├── commands_*.py
│   │   └── formatters.py
│   ├── analysis/             # Layer 4: Analysis
│   │   ├── scoring/
│   │   └── detectors/
│   ├── tools/                # Layer 5: Tools
│   │   ├── subfinder/
│   │   ├── naabu/
│   │   ├── dnsx/
│   │   └── httpx/
│   └── data/                 # Layer 6: Database
│       ├── database/
│       │   └── sqlmodel_manager.py
│       └── models/
├── tests/                    # 351 tests
├── openeasd.py              # CLI entry point
└── pyproject.toml           # Dependencies (uv)
```

---

## Technology Stack

- **API**: FastAPI 0.109+, Pydantic v2, Uvicorn
- **CLI**: Click 8.1.7
- **Database**: SQLite, SQLModel
- **Analysis**: Custom risk scoring engine
- **Tools**: Subfinder, Naabu, Dnsx, Httpx
- **Testing**: pytest (351 tests, 79% coverage)
- **Package Manager**: uv

---

## Quick Start

```bash
# Install dependencies
uv sync

# Start API server (read-only)
uv run uvicorn src.api.main:app --port 8000

# CLI operations
uv run python openeasd.py domain add example.com --primary
uv run python openeasd.py scan domain example.com
uv run python openeasd.py analysis findings
```

---

**Architecture Status**: 6-Layer (All Complete)
**Test Coverage**: 79% (351 tests passing)
**Last Updated**: December 2025
