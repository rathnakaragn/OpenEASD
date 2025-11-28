# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (6-Layer Design with Analysis)
**Version**: 9.0 - Production-ready with Analysis Layer
**Last Updated**: November 26, 2025
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Documentation

For detailed information about what each layer does, their responsibilities, and code examples, see:
- **[LAYER_ARCHITECTURE.md](./LAYER_ARCHITECTURE.md)** - Comprehensive layer-by-layer guide with code examples, data flows, and best practices

This document provides a high-level architecture overview. For in-depth layer explanations, refer to LAYER_ARCHITECTURE.md.

---

## Architecture Overview

OpenEASD implements enterprise-grade external attack surface detection through a comprehensive 6-layer architecture combining automated subdomain enumeration, port scanning, vulnerability detection, and risk analysis with both REST API and CLI interfaces.

### System Architecture (6-Layer Design)

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: API Layer (FastAPI) - Read-Only Monitoring ✅    │
│    • 24 REST endpoints for data access (GET only)          │
│    • Swagger/OpenAPI documentation                         │
│    • CORS support for integrations                         │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Service Layer - Shared Business Logic ✅         │
│    • Domain, Scan, Alert, Analysis services                │
│    • Dependency injection and service composition          │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: CLI Layer (Click) - Full Operations ✅           │
│    • Domain management (add/list/update/remove)            │
│    • Scan execution and orchestration                      │
│    • Analysis commands and findings management             │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Analysis Layer - Vulnerability Detection ✅      │
│    • Risk scoring (0-100 deterministic)                    │
│    • Port vulnerability analysis                           │
│    • Finding deduplication and management                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Tools Layer (Security Tools) ✅                  │
│    • Subfinder, Amass, Naabu, Dnsx, Nmap                  │
│    • Direct subprocess execution with JSON parsing         │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Database Layer (SQLite) ✅                       │
│    • SQLModel ORM with SQLite backend                      │
│    • Findings, vulnerabilities, CVE mappings               │
│    • Scan history and audit trails                         │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Status

| Layer | Status | Components | Coverage | Notes |
|-------|--------|------------|----------|-------|
| **Layer 1: API** | ✅ Complete | FastAPI, Pydantic schemas, CORS | 77% | 24 endpoints, read-only |
| **Layer 2: Service** | ✅ Complete | Domain, Scan, Alert, Analysis services | 85% | Shared business logic |
| **Layer 3: CLI** | ✅ Complete | Click commands, domain/scan/analysis | 92% | Full operations access |
| **Layer 4: Analysis** | ✅ Complete | Risk scorer, detectors, findings | 95% | Vulnerability detection |
| **Layer 5: Tools** | ✅ Complete | Subfinder, Amass, Naabu, etc. | 93% | Direct subprocess calls |
| **Layer 6: Database** | ✅ Complete | SQLite, SQLModel, findings schema | 77% | Data persistence |

**Test Coverage**: 79% overall (367/378 tests passing, 2,928/3,696 statements)

---

## Layer Implementation

### Layer 1: CLI Layer (Interface & Orchestration) ✅

**Purpose**: User interface, command handling, and security tool orchestration
**Technology Stack**: Click 8.1.7, Python 3.11+, Subprocess
**Status**: **Production Ready**

**Key Components**:
- **Main CLI** (`src/cli/main.py`): Click-based command-line interface
- **Scan Commands** (`src/cli/commands.py`): Tool execution and scan orchestration
- **Domain Commands** (`src/cli/commands_domain.py`): Domain management operations
- **Formatters** (`src/cli/formatters.py`): Multi-format output rendering

**Available Commands**:
```bash
# Scanning
openeasd scan domain <domain> [--timeout N] [--output FORMAT]
openeasd scan subfinder [--primary] [--timeout N]

# Domain Management
openeasd domain add <domain> [--primary] [--notes TEXT] [--tags CSV]
openeasd domain list [--primary] [--limit N]
openeasd domain update <domain> [--primary BOOL] [--notes TEXT]
openeasd domain remove <domain> [--force]
openeasd domain show <domain>

# History & Results
openeasd history [--limit N]
openeasd scans [--limit N]
openeasd results <scan-id> [--output FORMAT]
```

**Output Formats**:
- `table`: ASCII table with metadata (default)
- `json`: Structured JSON for programmatic use
- `csv`: Comma-separated values for spreadsheets
- `txt`: Plain text subdomain list
- `txt`: Plain text subdomain list (for piping to tools)

**Features**:
- ✅ Single organization model
- ✅ Domain management (add, list, update, remove)
- ✅ UUID-based scan IDs
- ✅ Scan duration tracking (IST timezone)
- ✅ Batch scanning for multiple domains
- ✅ Interactive deletion with preview

---

### Layer 2: Tools Layer (Security Tools) ✅

**Purpose**: Security tool execution via direct subprocess calls
**Technology Stack**: Subprocess, JSON parsing, IST timezone support
**Status**: **Production Ready**

**Key Components**:
- **Tool Modules** (`src/tools/`): Security tool runner implementations
  - **Subfinder** (`subfinder/`): Passive subdomain discovery
  - **Amass** (`amass/`): Comprehensive subdomain enumeration
  - **Nmap** (`nmap/`): Service detection and port scanning
  - **Naabu** (`naabu/`): Fast port scanning

**Execution Pattern**:
CLI Layer calls tools directly via subprocess:
```python
def run_subfinder(domain: str, timeout: int) -> List[str]:
    result = subprocess.run(
        ['subfinder', '-d', domain, '-silent', '-json'],
        capture_output=True, text=True, timeout=timeout
    )
    # Parse JSON output and return subdomains
    return subdomains
```

**Tool Capabilities**:

**Subfinder**:
- ✅ Passive DNS enumeration
- ✅ JSON output parsing
- ✅ Multiple data source integration
- ✅ Silent mode for clean output
- ✅ Configurable timeout

**Amass** (Module available):
- Passive + active enumeration modes
- Comprehensive data source coverage
- IP address resolution
- ASN and metadata extraction

**Nmap** (Module available):
- Service version detection
- Port scanning
- OS fingerprinting
- XML output parsing

**Naabu** (Module available):
- Fast SYN/CONNECT scanning
- Port discovery
- JSON output format
- Concurrent scanning

---

### Layer 3: Database Layer (Storage & Analytics) ✅

**Purpose**: Data persistence, querying, and analytics
**Technology Stack**: DuckDB 1.4.1, SQL, Python asyncio
**Status**: **Production Ready**

**Key Components**:
- **DuckDB Manager** (`src/data/database/duckdb_manager.py`): Database interface
- **Schema Management**: Table creation and migrations
- **Query Optimization**: Efficient JOINs and aggregations

**Database Schema**:

**Core Tables**:
```sql
-- Domain registry
domains (
    domain VARCHAR PRIMARY KEY,
    domain_type VARCHAR,  -- 'apex' or 'subdomain'
    is_primary BOOLEAN,
    notes TEXT,
    tags VARCHAR[],
    scan_frequency VARCHAR,
    created_at TIMESTAMP,
    last_scanned_at TIMESTAMP
)

-- Scan sessions
scan_sessions (
    scan_id VARCHAR PRIMARY KEY,
    scan_type VARCHAR,
    tool_name VARCHAR,
    domains_scanned VARCHAR[],
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    status VARCHAR,
    findings_count INTEGER
)

-- Subdomain history tracking
subdomain_history (
    id VARCHAR PRIMARY KEY,
    apex_domain VARCHAR,
    subdomain VARCHAR,
    scan_id VARCHAR,
    status VARCHAR,  -- 'new', 'existing', 'removed'
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
)

-- Security alerts
security_alerts (
    id VARCHAR PRIMARY KEY,
    domain VARCHAR,
    scan_id VARCHAR,
    alert_type VARCHAR,
    severity VARCHAR,
    description TEXT,
    discovered_at TIMESTAMP
)
```

**Tool-Specific Result Tables**:
```sql
-- Subfinder results
subfinder_results (scan_id, apex_domain, subdomain, discovered_at)

-- Amass results
amass_results (scan_id, apex_domain, subdomain, ip_address, asn, discovered_at)

-- Nmap results
nmap_results (scan_id, host, port, protocol, service, version, discovered_at)

-- Naabu results
naabu_results (scan_id, host, port, protocol, discovered_at)
```

**Features**:
- ✅ Single organization model (no multi-tenancy)
- ✅ UUID-based scan IDs
- ✅ Domain tracking with metadata (notes, tags, frequency)
- ✅ Subdomain change detection (new/existing/removed)
- ✅ Scan history with aggregations
- ✅ Timezone-aware timestamps (IST)
- ✅ Efficient JOINs and aggregations
- ✅ Data deletion with preview
- ✅ No indexes on scan_sessions (DuckDB limitation workaround)

**Query Examples**:
```sql
-- Get domain scan summary with accurate counts
SELECT d.domain, COUNT(DISTINCT s.scan_id) as scan_count
FROM domains d
LEFT JOIN scan_sessions s ON s.domains_scanned[1] = d.domain
GROUP BY d.domain;

-- Get scan history with latest status
SELECT domain,
       ARG_MAX(status, start_time) as latest_status,
       COUNT(*) as total_scans
FROM scan_sessions
GROUP BY domain;
```

---

## Project Structure

### 3-Layer Directory Structure

```
OpenEASD/
├── src/                        # Source code directory
│   ├── cli/                    # Layer 1: CLI Layer ✅
│   │   ├── __init__.py
│   │   ├── main.py            # Click CLI application entry point
│   │   ├── commands.py        # Scan command implementations
│   │   ├── commands_domain.py # Domain management commands
│   │   └── formatters.py      # Output formatters (table/json/csv/txt)
│   │
│   ├── tools/                  # Layer 2: Tools Layer ✅
│   │   ├── subfinder/         # Passive subdomain discovery
│   │   │   ├── __init__.py
│   │   │   └── runner.py
│   │   ├── amass/             # Comprehensive subdomain enumeration
│   │   │   ├── __init__.py
│   │   │   └── runner.py
│   │   ├── nmap/              # Service detection and port scanning
│   │   │   ├── __init__.py
│   │   │   └── runner.py
│   │   └── naabu/             # Fast port scanning
│   │       ├── __init__.py
│   │       └── runner.py
│   │
│   ├── data/                   # Layer 3: Database Layer ✅
│   │   ├── __init__.py
│   │   ├── database/          # DuckDB implementation
│   │   │   ├── duckdb_manager.py
│   │   │   └── organization_manager.py (legacy)
│   │   └── migrations/        # Schema migrations
│   │
│   ├── core/                   # Core infrastructure
│   │   ├── interfaces/        # Shared interfaces
│   │   ├── scanner/           # Scanner implementation
│   │   └── security/          # Security utilities
│   │
│   └── utils/                  # Common utilities
│       ├── config.py          # Configuration management
│       ├── logging.py         # Logging setup
│       └── timezone.py        # Timezone utilities (IST)
│
├── data/                       # Database storage
│   └── openeasd.db            # DuckDB database file
│
├── config/                     # Configuration files
│   └── recon_config.yaml      # Tool configuration
│
├── tests/                      # Test suite (future)
│
├── requirements.txt            # Python dependencies
├── openeasd.py                 # CLI entry point script
├── README.md                   # Project overview
├── CLAUDE.md                   # AI assistant guide
└── DESIGN.md                   # Architecture documentation
```

---

## Data Flow Architecture

### Scan Workflow (3-Layer Flow)

```
User Command
    ↓
┌─────────────────────────────────────┐
│  Layer 1: CLI Layer                 │
│  • Parse command arguments          │
│  • Validate domain input            │
│  • Initialize scan session          │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Layer 2: Tools Layer               │
│  • Execute: subfinder -d domain     │
│  • Parse JSON output                │
│  • Extract subdomains               │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Layer 3: Database Layer            │
│  • Store scan session               │
│  • Store subfinder results          │
│  • Track subdomain changes          │
│  • Generate security alerts         │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Layer 1: CLI Layer                 │
│  • Format output (table/json/csv)   │
│  • Display results to user          │
└─────────────────────────────────────┘
```

### Domain Management Workflow

```
User: openeasd domain add example.com --primary
    ↓
CLI Layer: Parse and validate
    ↓
Database Layer: Insert into domains table
    ↓
CLI Layer: Display confirmation
```

---

## System Design Principles

### 1. 5-Layer Separation
**Rationale**: Clean separation of concerns with single responsibility per layer
- User interface separate from data collection
- Data collection separate from analysis
- Analysis separate from notification
- All layers separate from storage

### 2. Modular Architecture
**Implementation**: Each layer contains modular components
- Easy to swap tool implementations
- Interface-based design
- Independent testing
- Plugin architecture

### 3. Async-First Design
**Technology**: Python asyncio throughout
- Non-blocking operations
- Efficient resource utilization
- Scalable processing
- Parallel tool execution

### 4. Interface-Based Contracts
**Pattern**: Abstract interfaces for all major components
- Enables dependency injection
- Supports testing with mocks
- Facilitates future enhancements
- Consistent patterns across layers

---

## Workflow

### Current Scan Execution Flow

```
1. User runs: openeasd scan example.com --org "Example"
2. CLI Layer validates input
3. Recon Layer executes tools:
   - Subfinder discovers subdomains
   - Results stored to database
4. Database Layer persists findings
5. CLI Layer displays results
```

### Future Scan Execution Flow (with Analysis + Notification)

```
1. User runs: openeasd scan example.com --org "Example"
2. CLI Layer validates input
3. Recon Layer executes tools:
   - Subfinder discovers subdomains
   - Amass enriches data
   - Nmap scans services
   - Naabu scans ports
4. Analysis Layer analyzes findings:
   - Detects vulnerabilities
   - Calculates risk scores
   - Classifies threats
5. Notification Layer generates alerts:
   - Filters by severity
   - Sends to configured channels
6. Database Layer persists all data
7. CLI Layer displays results
```

---

## Summary

OpenEASD implements focused external attack surface detection through a **5-layer modular architecture**. The system currently has **3 layers fully implemented** (CLI, Recon, Database) with **2 layers planned** (Analysis, Notification).

**Current Scope**:
- ✅ Command-line interface with multiple output formats
- ✅ Subdomain enumeration (Subfinder, Amass)
- ✅ Port scanning (Nmap, Naabu)
- ✅ DuckDB storage with organization tracking
- ✅ Scan history and results management

**Planned Expansion**:
- ⏳ Vulnerability detection and risk scoring (Analysis Layer)
- ⏳ Alert generation and multi-channel notifications (Notification Layer)

**Key Advantages**:
- ✅ Clean separation of concerns
- ✅ Modular, extensible architecture
- ✅ Interface-based design patterns
- ✅ Async execution for performance
- ✅ Multiple output formats
- ✅ Organization-based data management

---

**Architecture Status**: 5-Layer Design (3 Implemented, 2 Planned)
**Scope**: Subdomain Enumeration + Port Scanning + Analysis + Notifications
**Deployment**: CLI-based with future API expansion
**Last Updated**: October 2025
