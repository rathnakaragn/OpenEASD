# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (6-Layer Design)
**Version**: 12.0
**Last Updated**: December 2025
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Quick Reference

For detailed layer-by-layer documentation with code examples, see:
- **[LAYER_ARCHITECTURE.md](./LAYER_ARCHITECTURE.md)** - Comprehensive guide with data flows and best practices

This document provides a high-level architecture overview.

---

## Architecture Overview

OpenEASD implements external attack surface detection through a **6-layer architecture** combining:
- Automated subdomain enumeration
- Port scanning
- Vulnerability detection
- Risk analysis
- REST API and CLI interfaces

### Security Model

**Read-Only API + Full-Access CLI**

| Interface | Access Level | Use Cases |
|-----------|--------------|-----------|
| **API** | Read-only (GET only) | Monitoring, dashboards, integrations |
| **CLI** | Full access (CRUD) | Operations, scanning, configuration |

This separation minimizes attack surface while enabling remote monitoring.

---

## 6-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: API Layer (FastAPI)                                    │
│ Purpose: Read-only REST API for monitoring                      │
│ Access: Remote (HTTP), GET endpoints only                       │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Service Layer                                          │
│ Purpose: Shared business logic between API and CLI              │
│ Components: DomainService, ScanService, FindingsService         │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: CLI Layer (Click)                                      │
│ Purpose: Full-featured command-line interface                   │
│ Access: Local shell, Full CRUD operations                       │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: Analysis Layer                                         │
│ Purpose: Automated vulnerability detection and risk scoring     │
│ Components: RiskScorer, Detectors, Finding management           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 5: Tools Layer                                            │
│ Purpose: Execute external security tools                        │
│ Tools: Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap               │
├─────────────────────────────────────────────────────────────────┤
│ Layer 6: Database Layer (SQLite + SQLModel)                     │
│ Purpose: Persistent data storage                                │
│ Storage: data/openeasd.db                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer Responsibilities

### Layer 1: API Layer
- HTTP request handling with FastAPI
- Pydantic v2 schema validation
- Rate limiting and CORS
- OpenAPI/Swagger documentation

### Layer 2: Service Layer
- Domain CRUD operations
- Scan orchestration
- Findings management
- Analysis coordination
- Dependency injection

### Layer 3: CLI Layer
- Click-based command parsing
- Domain management commands
- Scan execution commands
- Analysis commands
- Multi-format output (table, json, csv, txt)
- Real-time progress display

### Layer 4: Analysis Layer
- Risk scoring (0-100 deterministic scale)
- Port vulnerability detection
- Finding deduplication
- CVE mapping support
- Remediation guidance

### Layer 5: Tools Layer
- Subprocess execution
- JSON output parsing
- Timeout management
- Error handling
- Tool integrations: Subfinder, Naabu, Dnsx, Httpx

### Layer 6: Database Layer
- SQLite with SQLModel ORM
- 15+ tables including: domains, scans, findings, vulnerabilities
- Timezone-aware timestamps (IST)
- Efficient queries and aggregations

---

## Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| API | FastAPI | 0.109+ |
| API | Pydantic | 2.5+ |
| API | Uvicorn | 0.27+ |
| CLI | Click | 8.1.7 |
| Database | SQLModel | - |
| Database | SQLite | 3.x |
| Runtime | Python | 3.11+ |

---

## Data Flow

### API Path (Read-Only)

```
HTTP Request → API Layer → Service Layer → Database Layer
                                ↓
              Response ← Service Layer ← Query Results
```

### CLI Path (Full Access)

```
User Command → CLI Layer → Service Layer → Tools Layer
                              ↓               ↓
                         Database Layer   Analysis Layer
                              ↓
              Display ← CLI Layer ← Results
```

---

## Project Structure

```
OpenEASD/
├── src/
│   ├── api/              # Layer 1: REST API
│   │   ├── main.py       # FastAPI application
│   │   ├── routes/       # API endpoints
│   │   └── schemas/      # Pydantic models
│   ├── services/         # Layer 2: Business logic
│   │   ├── domain_service.py
│   │   ├── scan_service.py
│   │   └── findings_service.py
│   ├── cli/              # Layer 3: CLI interface
│   │   ├── main.py       # Click application
│   │   ├── commands_*.py # Command implementations
│   │   └── formatters.py # Output formatting
│   ├── analysis/         # Layer 4: Vulnerability detection
│   │   ├── analysis_service.py
│   │   ├── scoring/      # Risk scoring
│   │   └── detectors/    # Detection modules
│   ├── tools/            # Layer 5: Security tools
│   │   ├── subfinder/
│   │   ├── naabu/
│   │   ├── dnsx/
│   │   ├── httpx/
│   │   └── tlsx/
│   ├── data/             # Layer 6: Database
│   │   ├── database/     # SQLModel manager
│   │   └── models/       # Data models (including findings)
│   ├── core/             # Interfaces and contracts
│   └── utils/            # Utilities (config, timezone, logging)
├── data/                 # Database storage
├── tests/                # Test suite
└── docs/                 # Documentation
```

---

## Implementation Status

| Layer | Status | Test Coverage |
|-------|--------|---------------|
| API Layer | Complete | 77% |
| Service Layer | Complete | 85% |
| CLI Layer | Complete | 92% |
| Analysis Layer | Complete | 95% |
| Tools Layer | Complete | 93% |
| Database Layer | Complete | 77% |

**Overall**: 79% coverage, 389+ tests passing

---

## Design Principles

1. **Separation of Concerns**: Each layer has specific responsibilities
2. **Security by Design**: API read-only, CLI full-access
3. **Loose Coupling**: Layers communicate through well-defined interfaces
4. **Dependency Injection**: Services injected at runtime
5. **Single Responsibility**: Each component does one thing well
6. **Extensibility**: Easy to add detectors, tools, or endpoints
7. **Proper Layering**: Lower layers don't depend on higher layers

---

## Quick Start

### API Server
```bash
uv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
# API docs: http://localhost:8000/api/docs
```

### CLI
```bash
# Domain management
uv run python openeasd.py domain add example.com --primary
uv run python openeasd.py domain list

# Scanning
uv run python openeasd.py scan domain example.com

# Analysis
uv run python openeasd.py analysis findings --severity high
```

---

**Last Updated**: December 2025
**Architecture Version**: 6-Layer
**Status**: Production-ready
