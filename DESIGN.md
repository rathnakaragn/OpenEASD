# OpenEASD System Architecture

**Company**: Cybersecify
**Author**: Rathnakara G N
**Document Type**: Architecture Overview (5-Layer Design)
**Version**: 6.0 - Current Implementation + Planned Expansion
**Last Updated**: October 2025
**Target Audience**: Architects, Technical Leads, Engineering Teams

---

## Architecture Overview

OpenEASD implements automated subdomain enumeration and port scanning through a modern 5-layer modular architecture focused on reconnaissance, analysis, and notification.

### System Architecture (5-Layer Design)

```
┌─────────────────────────────────────────────────────────────┐
│              OpenEASD - 5-Layer Architecture                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: CLI Layer (User Interface) ✅                     │
│    Commands: scan | history | results | delete | scans     │
│    Formats: table | json | csv | txt                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Recon Layer (Data Collection) ✅                  │
│    Subfinder | Amass | Nmap | Naabu                        │
│    Tool Execution | Output Parsing | Standardization       │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Analysis Layer (Planned) ⏳                       │
│    Vulnerability Detection | Risk Scoring                   │
│    Pattern Recognition | Threat Classification             │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Notification Layer (Planned) ⏳                   │
│    Alert Generation | Severity Filtering                   │
│    Multi-channel Routing | Template Rendering              │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Database Layer (Storage) ✅                       │
│    DuckDB | Schema Management | Query Optimization         │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Status

| Layer | Status | Components | Priority |
|-------|--------|------------|----------|
| **Layer 1: CLI** | ✅ Implemented | scan, history, results, delete, scans | - |
| **Layer 2: Recon** | ✅ Implemented | Subfinder, Amass, Nmap, Naabu | - |
| **Layer 3: Analysis** | ⏳ Planned | Vulnerability detection, risk scoring | Medium |
| **Layer 4: Notification** | ⏳ Planned | Alert generation, routing | Low |
| **Layer 5: Database** | ✅ Implemented | DuckDB, migrations | - |

---

## Layer Implementation

### Layer 1: CLI Layer (User Interface) ✅

**Purpose**: Command-line interface for scan operations and data retrieval
**Technology Stack**: Click, Python
**Status**: **Fully Implemented**

**Key Components**:
- **Main CLI** (`src/cli/main.py`): Entry point with Click commands
- **Commands** (`src/cli/commands.py`): Business logic for scan, history, results, delete
- **Formatters** (`src/cli/formatters.py`): Output formatting (table, json, csv, txt)

**Commands**:
```bash
openeasd scan <domain> [--org NAME] [--output FORMAT]
openeasd history [--limit N]
openeasd scans [--limit N]
openeasd results <scan-id> [--output FORMAT]
openeasd delete [--org NAME | --domain NAME] [--force]
```

**Output Formats**:
- `table`: ASCII table with metadata (default)
- `json`: Structured JSON for programmatic use
- `csv`: Comma-separated values for spreadsheets
- `txt`: Plain text subdomain list (for piping to tools)

**Features**:
- ✅ Default save to database
- ✅ Organization-based domain grouping
- ✅ UUID-based scan IDs
- ✅ Scan duration tracking
- ✅ Interactive deletion with preview

---

### Layer 2: Recon Layer (Data Collection) ✅

**Purpose**: Security tool execution and data gathering
**Technology Stack**: Subprocess, Python Asyncio
**Status**: **Fully Implemented**

**Key Components**:
- **Interfaces** (`src/recon/interfaces/tool.py`): ReconTool base class
- **Modules** (`src/recon/modules/`): Individual tool runners
  - **Subfinder** (`subfinder/runner.py`): Passive subdomain discovery
  - **Amass** (`amass/runner.py`): Comprehensive subdomain enumeration
  - **Nmap** (`nmap/runner.py`): Service detection and port scanning
  - **Naabu** (`naabu/runner.py`): Fast port scanning

**Architecture Pattern**:
All tools implement the `ReconTool` interface:
```python
class ReconTool(ABC):
    async def execute(target, options, timeout) -> ReconResult
    def parse_output(raw_output) -> Dict[str, Any]
    def validate_installation() -> bool
    def _build_command_args(target, options) -> List[str]
    def _extract_assets(parsed_data, target) -> List[Dict]
```

**Tool Capabilities**:

**Subfinder**:
- Passive DNS enumeration
- JSON output parsing
- Multiple data source integration
- Fast subdomain discovery

**Amass**:
- Passive + active enumeration modes
- Comprehensive data source coverage
- IP address resolution
- ASN and metadata extraction

**Nmap**:
- Service version detection
- XML output parsing
- OS detection support
- NSE script scanning

**Naabu**:
- High-speed port scanning
- Top ports scanning
- Protocol detection

---

### Layer 3: Analysis Layer (Planned) ⏳

**Purpose**: Vulnerability detection and risk assessment
**Technology Stack**: Python, Pattern Matching, ML (future)
**Status**: **Not Yet Implemented**

**Planned Components**:
- **Vulnerability Detectors**: Pattern-based security issue detection
- **Risk Scoring Engine**: CVSS-based risk calculation
- **Threat Classifiers**: Categorize findings by severity
- **Asset Intelligence**: Enrich discovered assets with context

**Planned Features**:
- 🔲 Detect exposed admin panels
- 🔲 Identify development/staging environments
- 🔲 Flag dangerous service versions
- 🔲 Detect misconfigured services
- 🔲 Calculate risk scores
- 🔲 Generate vulnerability reports

**Planned Directory Structure**:
```
src/analysis/
├── __init__.py
├── interfaces/
│   └── analyzer.py
├── detectors/
│   ├── exposure_detector.py
│   ├── version_detector.py
│   └── config_detector.py
├── scorers/
│   └── risk_scorer.py
└── classifiers/
    └── threat_classifier.py
```

---

### Layer 4: Notification Layer (Planned) ⏳

**Purpose**: Alert generation and notification routing
**Technology Stack**: Python, Email/Slack/Webhooks (future)
**Status**: **Not Yet Implemented**

**Planned Components**:
- **Alert Generator**: Create alerts from analysis findings
- **Severity Filter**: Filter alerts by severity threshold
- **Channel Routers**: Route alerts to multiple channels
- **Template Engine**: Format alerts for different channels

**Planned Features**:
- 🔲 Generate alerts for high-risk findings
- 🔲 Email notifications
- 🔲 Slack integration
- 🔲 Webhook support
- 🔲 Alert templates
- 🔲 Notification preferences

**Planned Directory Structure**:
```
src/notification/
├── __init__.py
├── interfaces/
│   └── notifier.py
├── generators/
│   └── alert_generator.py
├── channels/
│   ├── email_notifier.py
│   ├── slack_notifier.py
│   └── webhook_notifier.py
└── templates/
    ├── email.html
    └── slack.json
```

---

### Layer 5: Database Layer (Storage) ✅

**Purpose**: Data persistence and query management
**Technology Stack**: DuckDB, SQL
**Status**: **Fully Implemented**

**Key Components**:
- **DuckDB Manager** (`src/data/database/duckdb_manager.py`): Database operations
- **Migrations** (`src/data/migrations/`): Schema version control
- **Schemas**: Domain tracking, scan sessions, security alerts

**Database Schema**:
```sql
-- Domain management
CREATE TABLE domains (
    domain VARCHAR PRIMARY KEY,
    organization VARCHAR,
    is_primary BOOLEAN,
    created_at TIMESTAMP
);

-- Scan tracking
CREATE TABLE scan_sessions (
    scan_id VARCHAR PRIMARY KEY,
    scan_type VARCHAR,
    domains_scanned VARCHAR[],
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    status VARCHAR,
    findings_count INTEGER
);

-- Security findings
CREATE TABLE security_alerts (
    alert_id VARCHAR PRIMARY KEY,
    domain VARCHAR,
    scan_id VARCHAR,
    vulnerability_type VARCHAR,
    severity VARCHAR,
    description TEXT,
    tool_source VARCHAR,
    discovered_at TIMESTAMP
);
```

**Features**:
- ✅ UUID-based scan IDs
- ✅ Organization-based domain grouping
- ✅ Scan history tracking
- ✅ Timezone-aware timestamps (IST)
- ✅ Efficient querying
- ✅ Data deletion with preview

---

## Project Structure

### 5-Layer Directory Structure

```
OpenEASD/
├── src/                        # Source code directory
│   ├── cli/                    # Layer 1: CLI Layer ✅
│   │   ├── __init__.py
│   │   ├── main.py            # Click CLI application
│   │   ├── commands.py        # Command implementations
│   │   └── formatters.py      # Output formatters
│   │
│   ├── recon/                  # Layer 2: Recon Layer ✅
│   │   ├── __init__.py
│   │   ├── interfaces/        # Abstract contracts
│   │   │   └── tool.py        # ReconTool base class
│   │   ├── modules/           # Security tool modules
│   │   │   ├── subfinder/     # Subdomain discovery
│   │   │   │   ├── __init__.py
│   │   │   │   └── runner.py
│   │   │   ├── amass/         # Comprehensive enumeration
│   │   │   │   ├── __init__.py
│   │   │   │   └── runner.py
│   │   │   ├── nmap/          # Service detection
│   │   │   │   ├── __init__.py
│   │   │   │   └── runner.py
│   │   │   └── naabu/         # Port scanning
│   │   │       ├── __init__.py
│   │   │       └── runner.py
│   │   ├── orchestrators/     # Tool orchestration
│   │   ├── parsers/           # Output parsers
│   │   └── collectors/        # Data collectors
│   │
│   ├── analysis/               # Layer 3: Analysis Layer (Planned) ⏳
│   │   └── (not yet implemented)
│   │
│   ├── notification/           # Layer 4: Notification Layer (Planned) ⏳
│   │   └── (not yet implemented)
│   │
│   ├── data/                   # Layer 5: Database Layer ✅
│   │   ├── __init__.py
│   │   ├── database/          # DuckDB implementation
│   │   │   └── duckdb_manager.py
│   │   └── migrations/        # Schema migrations
│   │
│   ├── core/                  # Core infrastructure
│   │   ├── interfaces/        # Shared interfaces
│   │   ├── scanner/           # Scanner implementation
│   │   └── security/          # Security utilities
│   │
│   └── utils/                 # Common utilities
│       ├── logging.py         # Logging setup
│       └── timezone.py        # Timezone utilities (IST)
│
├── config/                     # Configuration files
├── tests/                      # Test suite
├── docs/                       # Layer documentation
│   ├── 00-CLI.md              # CLI Layer guide
│   ├── 01-RECON.md            # Recon Layer guide
│   ├── 02-ANALYSIS.md         # Analysis Layer guide (planned)
│   ├── 03-NOTIFICATION.md     # Notification Layer guide (planned)
│   └── 04-DATABASE.md         # Database Layer guide
├── requirements.txt           # Python dependencies
├── openeasd.py                # CLI entry point
└── README.md                  # Project overview
```

---

## Data Flow Architecture

### Current Implementation Flow

```
User Command (CLI)
    ↓
CLI Layer (parse arguments)
    ↓
Recon Layer (execute tools: Subfinder, Amass, Nmap, Naabu)
    ↓
Database Layer (store results in DuckDB)
    ↓
CLI Layer (format and display results)
```

### Future Complete Flow (with Analysis + Notification)

```
User Command (CLI)
    ↓
CLI Layer (parse arguments)
    ↓
Recon Layer (execute tools)
    ↓
Analysis Layer (detect vulnerabilities, score risks) ⏳
    ↓
Notification Layer (generate alerts, send notifications) ⏳
    ↓
Database Layer (store results and alerts)
    ↓
CLI Layer (format and display results)
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
