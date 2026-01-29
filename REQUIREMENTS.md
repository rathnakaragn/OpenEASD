# OpenEASD Product Requirements Document (PRD)

**Product:** OpenEASD — Automated External Attack Surface Detection
**Author:** Rathnakara G N / Cybersecify
**Version:** 4.0
**Last Updated:** January 29, 2026
**Target Audience:** Product Managers, Engineering, Security Analysts, Operations

---

## Implementation Status Summary

> **Current State (January 2026)**: Core scanning infrastructure is complete with a 6-layer API-only architecture. The system supports single-organization scanning with full CRUD API, 8-step scan workflow, and automated vulnerability detection.

| Category | Status | Notes |
|----------|--------|-------|
| **Core Scanning** | ✅ Complete | 7 security tools integrated |
| **API Layer** | ✅ Complete | Full CRUD REST API |
| **Risk Scoring** | ✅ Complete | Deterministic 0-100 scoring |
| **Web Dashboard** | ✅ Complete | Real-time scan monitoring |
| **Database** | ✅ Complete | SQLite with SQLModel ORM |
| **Job Queue** | ✅ Complete | Database-backed async processing |
| **Multi-Tenancy** | 🔲 Planned | Phase 2 |
| **Notifications** | 🔲 Planned | Slack/Email/PagerDuty |
| **Reporting** | 🔲 Planned | PDF executive reports |
| **Integrations** | 🔲 Planned | Jira/GitHub export |

---

## 1. Executive Summary

OpenEASD is an automated external attack surface detection system that performs unauthenticated security assessments of internet-facing assets. The system discovers subdomains, scans ports, identifies services, and detects vulnerabilities to provide organizations with visibility into their external attack surface.

**Current Capabilities:**
- Passive and active subdomain discovery
- Port scanning and service detection
- TLS/SSL verification
- Web misconfiguration detection (Nuclei)
- Vulnerability scanning (Nmap NSE + Nuclei)
- Automated risk scoring and prioritization
- Web dashboard for monitoring
- Full CRUD REST API

**Planned Capabilities:**
- Multi-tenant organization management
- Notification channels (Slack, Email, PagerDuty)
- Executive PDF reports
- Jira/GitHub integration
- Scheduled scan cadences

---

## 2. Goals and Success Metrics

### Current Goals (Phase 1 - Achieved)
- ✅ Automated external attack surface scanning
- ✅ Subdomain discovery and DNS resolution
- ✅ Port scanning with service identification
- ✅ Vulnerability detection with risk scoring
- ✅ Web-based dashboard for monitoring
- ✅ RESTful API for integration

### Future Goals (Phase 2+)
- 🔲 Multi-tenant support for multiple organizations
- 🔲 Configurable scan schedules (daily/weekly/monthly)
- 🔲 Real-time notifications for critical findings
- 🔲 Executive reporting with PDF export
- 🔲 Integration with ticketing systems

### Success Metrics
| Metric | Target | Current |
|--------|--------|---------|
| Time to first scan | ≤ 5 minutes | ✅ Achieved |
| Scan completion rate | ≥ 95% | ✅ Achieved |
| False positive rate | ≤ 10% | Measuring |
| API response time | ≤ 200ms | ✅ Achieved |
| System availability | ≥ 99% | ✅ Achieved |

---

## 3. Scope

### Implemented (Phase 1)

**Scanning Capabilities:**
- ✅ Passive subdomain discovery (Subfinder)
- ✅ DNS resolution and filtering (Dnsx)
- ✅ Fast TCP port scanning (Naabu)
- ✅ HTTP/HTTPS probing (Httpx)
- ✅ TLS/SSL verification (Tlsx)
- ✅ Service detection (Nmap -sV)
- ✅ Vulnerability scanning (Nmap NSE + Nuclei)

**Analysis & Reporting:**
- ✅ Risk scoring (0-100 deterministic scale)
- ✅ Severity classification (Critical/High/Medium/Low/Info)
- ✅ Finding deduplication
- ✅ Web dashboard with real-time updates
- ✅ JSON API for all data

**Infrastructure:**
- ✅ 6-layer API-only architecture
- ✅ Database-backed job queue
- ✅ Background worker processing
- ✅ Stale job recovery
- ✅ MCP server for Claude Code integration

### Planned (Phase 2)

**Multi-Tenancy:**
- 🔲 Organization management
- 🔲 Per-org data isolation
- 🔲 Bulk onboarding via CSV/API

**Notifications:**
- 🔲 Slack webhooks
- 🔲 Email alerts (HTML + PDF)
- 🔲 PagerDuty integration
- 🔲 Configurable cadences

**Reporting:**
- 🔲 Executive PDF summaries
- 🔲 CSV/JSON export
- 🔲 Jira/GitHub templates

### Out of Scope
- Authenticated/credentialed scanning
- Internal network scanning
- Full ticketing system (integrations only)
- ML-powered false positive reduction
- Billing and payment processing

---

## 4. Users and Personas

| Persona | Needs | Current Support |
|---------|-------|-----------------|
| **Security Analyst** | Triage findings, validate vulnerabilities | ✅ Dashboard, API |
| **DevOps Engineer** | View scan results, track remediation | ✅ API, findings status |
| **Technical Lead** | Monitor attack surface, prioritize fixes | ✅ Risk scoring, dashboard |
| **Platform Admin** | Manage domains, configure scans | ✅ Full CRUD API |

---

## 5. Functional Requirements

### 5.1 Domain Management ✅ Implemented

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Add/remove domains | ✅ | `POST/DELETE /api/v1/domains` |
| List all domains | ✅ | `GET /api/v1/domains` |
| Domain metadata (notes, tags) | ✅ | Domain model fields |
| Primary domain designation | ✅ | `is_primary` flag |
| Scan frequency setting | ✅ | `scan_frequency` field |

### 5.2 Scanning Capabilities ✅ Implemented

| Capability | Tool | Status |
|------------|------|--------|
| Subdomain discovery | Subfinder | ✅ |
| DNS resolution | Dnsx | ✅ |
| Port scanning | Naabu | ✅ |
| HTTP probing | Httpx | ✅ |
| TLS verification | Tlsx | ✅ |
| Service detection | Nmap | ✅ |
| Vulnerability scanning | Nmap NSE + Nuclei | ✅ |

**8-Step Scan Workflow:**
1. `step1_discover_subdomains` - Subfinder
2. `step2_resolve_dns` - Dnsx
3. `step3_scan_ports` - Naabu
4. `step4_probe_http` - Httpx
5. `step5_verify_tls` - Tlsx
6. `step6_detect_services` - Nmap -sV
7. `step7_detect_vulnerabilities` - Nmap NSE + Nuclei
8. `step8_analyze` - Risk scoring

### 5.3 Risk Scoring ✅ Implemented

**Scoring Algorithm (0-100):**
- Base score (0-40): Inherent risk of finding type
- Context score (0-40): Business context and asset criticality
- Exposure score (0-20): Public accessibility

**Severity Mapping:**
| Score Range | Severity |
|-------------|----------|
| 80-100 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| 20-39 | Low |
| 0-19 | Info |

### 5.4 Finding Management ✅ Implemented

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| List findings | ✅ | `GET /api/v1/findings` |
| Filter by severity | ✅ | Query parameters |
| Update finding status | ✅ | `PUT /api/v1/findings/{id}` |
| Finding statistics | ✅ | `GET /api/v1/findings/stats` |
| Status workflow | ✅ | new → open → acknowledged → resolved/false_positive |

### 5.5 Notifications 🔲 Planned

| Requirement | Status | Priority |
|-------------|--------|----------|
| Slack webhooks | 🔲 | High |
| Email alerts | 🔲 | High |
| PagerDuty integration | 🔲 | Medium |
| Configurable cadences | 🔲 | Medium |

### 5.6 Reporting 🔲 Planned

| Requirement | Status | Priority |
|-------------|--------|----------|
| Executive PDF summary | 🔲 | High |
| CSV export | 🔲 | Medium |
| JSON export | ✅ | Complete (API) |
| Jira templates | 🔲 | Low |
| GitHub issue templates | 🔲 | Low |

---

## 6. Non-Functional Requirements

| Requirement | Target | Current Status |
|-------------|--------|----------------|
| API response time | ≤ 200ms | ✅ Achieved |
| Scan timeout | Configurable (default 300s) | ✅ Implemented |
| Concurrent scans | Multiple via workers | ✅ Implemented |
| Data persistence | SQLite with backups | ✅ Implemented |
| Job recovery | Stale job detection (30 min) | ✅ Implemented |
| Graceful shutdown | Signal handling | ✅ Implemented |

---

## 7. Current Architecture

### 6-Layer API-Only Design

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: API Layer (FastAPI)                                │
│   - Full CRUD REST API                                      │
│   - Pydantic v2 validation                                  │
│   - Web dashboard served at /                               │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Orchestrator Layer                                 │
│   - DomainService, ScanService, FindingsService             │
│   - JobService, HealthService                               │
│   - ScanWorkflowOrchestrator (8-step workflow)              │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Database Job Queue                                 │
│   - Jobs stored in SQLite                                   │
│   - Worker polls for pending jobs                           │
│   - Atomic claiming with worker ID                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Tools Layer                                        │
│   - Subfinder, Naabu, Dnsx, Httpx, Tlsx, Nmap, Nuclei       │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Analysis Layer                                     │
│   - RiskScorer, PortVulnerabilityDetector, ServiceDetector  │
├─────────────────────────────────────────────────────────────┤
│ Layer 6: Database Layer (SQLite + SQLModel)                 │
│   - 15+ tables for domains, scans, findings, jobs           │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology |
|-----------|------------|
| API Framework | FastAPI 0.109+ |
| Validation | Pydantic v2 |
| Database | SQLite + SQLModel |
| Job Queue | Database polling |
| Package Manager | uv |
| Testing | pytest |
| MCP Integration | fastmcp |

---

## 8. API Endpoints

### Implemented Endpoints

```
# Health
GET  /api/v1/health                     # Health check

# Domains (Full CRUD)
GET  /api/v1/domains                    # List domains
POST /api/v1/domains                    # Create domain
GET  /api/v1/domains/{domain}           # Get domain details
PUT  /api/v1/domains/{domain}           # Update domain
DELETE /api/v1/domains/{domain}         # Delete domain

# Scans (Async)
GET  /api/v1/scans                      # List scans
POST /api/v1/scans                      # Create scan (returns 202)
GET  /api/v1/scans/{scan_id}            # Get scan status
GET  /api/v1/scans/{scan_id}/results    # Get scan results
DELETE /api/v1/scans/{scan_id}          # Delete scan
POST /api/v1/scans/{scan_id}/cancel     # Cancel scan
POST /api/v1/scans/{scan_id}/retry      # Retry failed scan

# Findings
GET  /api/v1/findings                   # List findings
GET  /api/v1/findings/{id}              # Get finding details
PUT  /api/v1/findings/{id}              # Update finding status
GET  /api/v1/findings/stats             # Get statistics

# Jobs
GET  /api/v1/jobs                       # List jobs
GET  /api/v1/jobs/{id}                  # Get job status
GET  /api/v1/jobs/stats                 # Get job statistics
```

---

## 9. Roadmap

### Phase 1 - Core Scanning ✅ Complete (January 2026)
- ✅ 6-layer API-only architecture
- ✅ 7 security tools integrated
- ✅ 8-step scan workflow
- ✅ Risk scoring and analysis
- ✅ Web dashboard
- ✅ Full CRUD API
- ✅ Database job queue
- ✅ MCP server integration

### Phase 2 - Notifications & Reporting (Planned)
- 🔲 Slack webhook integration
- 🔲 Email notifications
- 🔲 Executive PDF reports
- 🔲 CSV export functionality
- 🔲 Scheduled scan cadences

### Phase 3 - Multi-Tenancy (Planned)
- 🔲 Organization management
- 🔲 Per-org data isolation
- 🔲 Role-based access control
- 🔲 Bulk onboarding

### Phase 4 - Integrations (Planned)
- 🔲 Jira integration
- 🔲 GitHub issue creation
- 🔲 PagerDuty alerts
- 🔲 S3 storage for evidence

---

## 10. Quick Start

### Running the Application

```bash
# Install dependencies
uv sync

# Terminal 1: Start API server
python openeasd.py --port 8000

# Terminal 2: Start worker
python -m workers.scan_worker

# Access dashboard
open http://localhost:8000

# Access API docs
open http://localhost:8000/docs
```

### Basic API Usage

```bash
# Create a domain
curl -X POST http://localhost:8000/api/v1/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "is_primary": true}'

# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Check scan status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Get results
curl http://localhost:8000/api/v1/scans/{scan_id}/results
```

---

## 11. Security Considerations

- **Unauthenticated scanning only** - No credential-based testing
- **Safe defaults** - Non-intrusive scanning by default
- **Rate limiting** - Configurable scan rate limits
- **Data isolation** - Per-scan result isolation
- **Evidence retention** - Configurable retention policies

---

## 12. File Structure

```
OpenEASD/
├── src/
│   ├── api/                  # Layer 1: REST API
│   ├── orchestrator/         # Layer 2: Business logic
│   ├── analysis/             # Layer 5: Risk scoring
│   ├── tools/                # Layer 4: Security tools
│   ├── data/                 # Layer 6: Database
│   ├── frontend/             # Web dashboard
│   └── mcp/                  # MCP server
├── workers/
│   └── scan_worker.py        # Background job processor
├── tests/                    # Test suite
├── openeasd.py               # API entry point
└── pyproject.toml            # Dependencies
```

---

**Document Status:** Updated to reflect current implementation
**Last Updated:** January 29, 2026
**Version:** 4.0
