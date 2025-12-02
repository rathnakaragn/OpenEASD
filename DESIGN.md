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

**Purpose**: Security tool execution via subprocess with parallel execution optimization
**Tools**:
- **Subfinder**: Passive subdomain discovery
- **Naabu**: Fast port scanning
- **Dnsx**: DNS resolution
- **Httpx**: HTTP probing
- **Nmap**: Service detection and vulnerability scanning (NEW)

#### Nmap Service Detection & Vulnerability Scanning (Phase 3 & 3.5)

**Phase 3: Parallel Service Detection**
- **Function**: `run_nmap_service_detection_parallel(ports, max_workers=5)`
- **Purpose**: Identify running services on non-web ports with version information
- **Process**:
  1. Collects all non-web ports from httpx probing
  2. Executes parallel `nmap -sV` on 5 ports simultaneously
  3. Extracts service name, version, and confidence (0-100)
  4. Maps services to severity: CRITICAL (databases), HIGH (FTP/Telnet), MEDIUM (SSH/SMTP), LOW (NTP)
- **Performance**:
  - Sequential: ~4.6 seconds (46% overhead)
  - Parallel (5 workers): ~2.0 seconds (20% overhead) → **2.3x faster!**

**Example Output**:
```python
{
  'example.com:3306': {
    'service': 'mysql',
    'version': '5.7.30-0-log',
    'confidence': 95,
    'product': 'MySQL',
    'status': 'success'
  }
}
```

**Phase 3.5: Parallel Vulnerability Detection**
- **Function**: `run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)`
- **Purpose**: Detect known CVEs in identified services using NSE scripts
- **Process**:
  1. Runs service-specific NSE scripts: `--script=mysql-vuln*`, `postgresql-vuln*`, etc.
  2. Extracts CVE IDs using regex: `CVE-\d{4}-\d{4,5}`
  3. Maps CVE to CVSS scores and severity levels
  4. Generates remediation suggestions per service
- **Service-Specific Scripts**:
  - MySQL: `mysql-vuln*,mysql-enum`
  - PostgreSQL: `postgresql-vuln*`
  - MongoDB: `mongodb-enum`
  - Redis: `redis-info`
  - SSH: `ssh2-enum-algos`
  - HTTP/HTTPS: `http-vuln*`

**Example Vulnerability Detection Result**:
```python
{
  'vulnerabilities': [
    {
      'cve_id': 'CVE-2012-2122',
      'cvss_score': 9.8,
      'severity': 'critical',
      'description': 'MySQL Authentication Bypass'
    },
    {
      'cve_id': 'CVE-2016-6663',
      'cvss_score': 7.5,
      'severity': 'high',
      'description': 'MySQL Privilege Escalation'
    }
  ],
  'status': 'success'
}
```

#### Alert Generation with Service & CVE Details

Alerts now include:
- **Service Information**: `service_type`, `service_version`, `service_confidence`
- **CVE Information**: `cve_ids` (JSON list), `cvss_score`, `vulnerability_description`
- **Remediation Steps**: Service-specific fix recommendations
- **Detection Method**: httpx, nmap, or banner grabbing

**Alert Example**:
```python
{
  'scan_id': 'scan-123',
  'domain': 'example.com',
  'vulnerability_type': 'exposed_mysql_service',
  'service_type': 'mysql',
  'service_version': '5.7.30-0-log',
  'service_confidence': 95,
  'severity': 'critical',
  'cve_ids': '["CVE-2012-2122", "CVE-2016-6663", "CVE-2019-2627"]',
  'cvss_score': 9.8,
  'vulnerability_description': 'CVE-2012-2122 (CVSS 9.8): CRITICAL | CVE-2016-6663 (CVSS 7.5): HIGH',
  'remediation_steps': 'Update MySQL to the latest stable version. Current version has known vulnerabilities.'
}
```

#### Scan Workflow with Parallel Execution

**Before Phase 3 & 3.5**:
```
Subfinder (3s) → Dnsx (2s) → Naabu (4s) → Httpx (2s) → Nmap -sV (sequential, 4.6s)
Total: 15.6s
```

**After Phase 3 & 3.5**:
```
Subfinder (3s) → Dnsx (2s) → Naabu (4s) → Httpx (2s) → Nmap -sV (parallel, 2s) → Nmap --script=vuln (parallel, 8s)
Total: 21s (includes full vulnerability detection!)
Performance: Sequential vs. Nmap calls = 2.3x faster
```

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
│   │   ├── httpx/
│   │   └── nmap/ (NEW: service detection + NSE vuln scanning)
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
- **Tools**:
  - Subfinder (subdomain discovery)
  - Naabu (port scanning)
  - Dnsx (DNS resolution)
  - Httpx (HTTP probing)
  - **Nmap** (service detection + NSE vulnerability scanning) ✨ NEW
- **Parallel Execution**: ThreadPoolExecutor (5 workers for service detection, 3 for vulnerability detection)
- **Testing**: pytest (327 tests, 79%+ coverage including 22 vulnerability detection tests)
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

**Architecture Status**: 6-Layer (All Complete) + Phase 3 & 3.5 Features
**New Features**: Nmap service detection (Phase 1) + Parallel execution (Phase 3) + Vulnerability detection (Phase 3.5)
**Test Coverage**: 79%+ (327+ tests passing, including 22 new vulnerability detection tests)
**Last Updated**: December 2, 2025
