# OpenEASD - Automated External Attack Surface Detection

**Enterprise-grade external attack surface detection with automated analysis and risk scoring**

## Overview

OpenEASD is a comprehensive security scanning platform that automates subdomain discovery, port enumeration, and vulnerability analysis. It combines multiple security tools with intelligent analysis to identify and prioritize security risks across your external assets.

**Key Capabilities**:
- 🔍 Automated subdomain discovery with Subfinder
- 🔓 Fast port scanning with Naabu
- 📊 Intelligent vulnerability detection and risk scoring
- 🛡️ Security alerts and findings management
- 🌐 REST API for monitoring and integrations
- 💻 Full-featured CLI for operations
- 📈 Comprehensive scan history and analytics
- 🔐 API key-based authentication and rate limiting

## Project Status

**Version**: 2.0.0 | **Status**: Production-ready
**Test Coverage**: 79% (367/378 tests passing)
**Architecture**: 7-layer with Messaging, API, Analysis, and Real-time Events

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  1. API Layer (FastAPI) - Read-Only Monitoring             │
│     └─ 24 endpoints for data access (GET only)             │
├─────────────────────────────────────────────────────────────┤
│  2. Service Layer - Shared Business Logic                   │
│     └─ Domain, Scan, Alert, Analysis services              │
├─────────────────────────────────────────────────────────────┤
│  3. CLI Layer (Click) - Full Operations                     │
│     └─ Domain mgmt, scan execution, analysis commands       │
├─────────────────────────────────────────────────────────────┤
│  4. Analysis Layer - Vulnerability Detection               │
│     └─ Risk scoring, port analysis, findings management    │
├─────────────────────────────────────────────────────────────┤
│  5. Tools Layer - Security Tool Integration                │
│     └─ Subfinder, Amass, Naabu, Dnsx, Nmap               │
├─────────────────────────────────────────────────────────────┤
│  6. Database Layer (SQLite) - Data Persistence             │
│     └─ Scan history, findings, vulnerabilities, mappings   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# 1. Clone repository
git clone <repository-url>
cd OpenEASD

# 2. Install dependencies
uv sync

# 3. Install security tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### Run API Server

```bash
# Start read-only API on port 8000
uv run uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Access API documentation
# http://localhost:8000/api/docs
```

### Use CLI

```bash
# Add domains
uv run python openeasd.py domain add example.com --primary

# Run scans
uv run python openeasd.py scan domain example.com

# View findings
uv run python openeasd.py analysis findings --severity critical

# Check results
uv run python openeasd.py results <scan-id>
```

## Usage Examples

### Domain Management

```bash
# Add a domain
uv run python openeasd.py domain add example.com --primary --notes "Production"

# List domains
uv run python openeasd.py domain list

# Update domain
uv run python openeasd.py domain update example.com --primary false

# Remove domain
uv run python openeasd.py domain remove example.com
```

### Scanning

```bash
# Scan single domain
uv run python openeasd.py scan domain example.com

# Batch scan all domains
uv run python openeasd.py scan

# Scan primary domains only
uv run python openeasd.py scan --primary-only

# View scan results
uv run python openeasd.py results <scan-id>

# View scan history
uv run python openeasd.py history
```

### Analysis & Findings

```bash
# List all findings
uv run python openeasd.py analysis findings

# Filter by severity
uv run python openeasd.py analysis findings --severity critical

# Show finding details
uv run python openeasd.py analysis show <finding-id>

# Update finding status
uv run python openeasd.py analysis update <finding-id> resolved

# View statistics
uv run python openeasd.py analysis stats
```

### API Access

```bash
# List domains
curl http://localhost:8000/api/v1/domains

# Get scan status
curl http://localhost:8000/api/v1/scans/<scan-id>

# List findings
curl http://localhost:8000/api/v1/findings?severity=critical

# Get finding details
curl http://localhost:8000/api/v1/findings/<finding-id>

# Check health
curl http://localhost:8000/api/v1/health
```

## API Endpoints

### Health & Monitoring
- `GET /api/v1/health` - Health check

### Domains
- `GET /api/v1/domains` - List domains
- `GET /api/v1/domains/{domain}` - Domain details

### Scans
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/{scan_id}` - Scan status
- `GET /api/v1/scans/{scan_id}/results` - Scan results

### Findings
- `GET /api/v1/findings` - List findings (filterable)
- `GET /api/v1/findings/{finding_id}` - Finding details
- `GET /api/v1/findings/scan/{scan_id}` - Findings by scan
- `GET /api/v1/findings/asset/{asset_name}` - Findings by asset
- `GET /api/v1/findings/statistics/summary` - Finding statistics

### Alerts
- `GET /api/v1/alerts` - List alerts
- `GET /api/v1/alerts/statistics` - Alert statistics

## Security Model

### API (Read-Only)
**Purpose**: Monitoring, dashboards, integrations
**Access**: GET requests only
**Port**: 8000

### CLI (Full Access)
**Purpose**: Operations, configuration, scan execution
**Access**: Full read/write
**Authentication**: Local shell access

This separation ensures that monitoring access is safe while keeping sensitive operations local.

## Key Features

### 1. Automated Vulnerability Detection
- **Risk Scoring**: Deterministic 0-100 scale with breakdown
- **Port Analysis**: Database exposure, high-risk services, admin interfaces
- **Deduplication**: Automatic finding deduplication
- **CVE Mapping**: Ready for CVE integration

### 2. Comprehensive Scanning
- **Subfinder**: Passive subdomain discovery
- **Naabu**: Fast port enumeration
- **Dnsx**: DNS resolution and validation
- **Extensible**: Add more tools easily

### 3. Data Management
- **SQLite Backend**: Lightweight, no external DB needed
- **Scan History**: Track changes over time
- **Finding Management**: Status tracking (open, resolved, false_positive)
- **Audit Trail**: All operations logged

### 4. REST API
- **Read-Only**: Safe for external integrations
- **Swagger/OpenAPI**: Auto-generated documentation
- **CORS**: Cross-origin support
- **Comprehensive**: 24 endpoints covering all features

## Test Coverage

**Overall Coverage**: 79% (2,928/3,696 statements)

### Excellent Coverage (>90%)
- Analysis Layer: 95% - Risk scoring, vulnerability detection
- CLI Commands: 92% - All command implementations
- Tools Layer: 93% - Security tool integration
- Services Layer: 85% - Business logic

### Good Coverage (75-90%)
- API Routes: 77% - REST endpoints
- Database Layer: 77% - Data persistence
- Utilities: 91% - Config, validation, logging

### Test Statistics
- **378 total tests** - 367 passing, 11 failing
- **19 test modules** - Comprehensive coverage
- **56+ unit tests** - Analysis layer alone

See [TEST_COVERAGE_REPORT.md](./TEST_COVERAGE_REPORT.md) for detailed analysis.

## Technology Stack

### Core
- **Python**: 3.11+
- **API**: FastAPI 0.109+
- **CLI**: Click 8.1.7
- **Database**: SQLite with SQLModel ORM
- **Package Manager**: uv

### Security Tools
- **Subfinder**: Passive subdomain enumeration
- **Naabu**: Port scanning
- **Dnsx**: DNS resolution
- **Amass**: OSINT enumeration (optional)
- **Nmap**: Service detection (optional)

### Testing
- **Framework**: pytest 8.2.2
- **Coverage**: pytest-cov 7.0.0
- **Mocking**: unittest.mock

## Configuration

### Environment Variables
```bash
# Analysis configuration
ANALYSIS_ENABLED=true
RISK_SCORE_METHOD=deterministic

# Port analysis thresholds
HIGH_RISK_PORTS=23,21,3306,5432,6379,27017
DATABASE_PORTS=3306,5432,27017,6379

# Scan defaults
DEFAULT_SCAN_TIMEOUT=300
DEFAULT_PORT_LIMIT=1000
```

### Configuration Files
- `config/recon_config.yaml` - Reconnaissance settings
- `config/analysis_config.yaml` - Analysis settings

## Documentation

Comprehensive documentation available:
- **[CLAUDE.md](CLAUDE.md)** - AI assistant guide with implementation details
- **[DESIGN.md](DESIGN.md)** - Detailed system architecture and design decisions
- **[REQUIREMENTS.md](REQUIREMENTS.md)** - Business requirements and specifications
- **[TEST_COVERAGE_REPORT.md](TEST_COVERAGE_REPORT.md)** - Complete test coverage analysis

## Running Tests

```bash
# Run all tests with coverage
uv run pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_risk_scorer.py -v

# Run tests matching pattern
uv run pytest tests/ -k "analysis" -v

# Generate HTML coverage report
uv run pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html
```

## Development

### Project Structure
```
OpenEASD/
├── src/
│   ├── api/              # FastAPI REST API (layer 1)
│   ├── services/         # Business logic (layer 2)
│   ├── cli/              # Click CLI (layer 3)
│   ├── analysis/         # Analysis & scoring (layer 4)
│   ├── tools/            # Security tool wrappers (layer 5)
│   ├── data/             # Database layer (layer 6)
│   ├── core/             # Core interfaces
│   └── utils/            # Utilities
├── tests/                # Test suite (19 modules)
├── config/               # Configuration files
├── openeasd.py          # CLI entry point
├── CLAUDE.md            # AI assistant guide
├── DESIGN.md            # Architecture document
├── REQUIREMENTS.md      # Requirements document
└── README.md            # This file
```

### Common Development Tasks

**Adding a new API endpoint**:
1. Define Pydantic schema in `src/api/schemas/`
2. Add service method
3. Create GET endpoint in `src/api/routes/`
4. Add to `src/api/main.py` routes
5. Write tests

**Adding a security tool**:
1. Create `src/tools/{tool}/` directory
2. Implement tool wrapper
3. Add step to ScanWorkflowOrchestrator
4. Add tests

## Performance

- **Single domain scan**: ~2-5 minutes (depends on subdomain count)
- **Batch scan (10 domains)**: ~20-50 minutes
- **Memory footprint**: 50-200 MB depending on scan size
- **Database size**: ~100 KB per 1000 domains scanned

## Troubleshooting

**Subfinder not found**:
```bash
# Ensure it's installed and in PATH
which subfinder
# If not, install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Naabu requires elevated privileges**:
```bash
# Naabu needs CAP_NET_RAW for SYN scanning
sudo uv run python openeasd.py scan example.com
```

**API not starting**:
```bash
# Check port 8000 is available
lsof -i :8000
# Kill any process using port 8000
```

**Database locked errors**:
```bash
# Close other instances accessing the database
# SQLite has limited concurrent access
```

## Support & Contributing

For issues, questions, or contributions:
1. Check [CLAUDE.md](./CLAUDE.md) for implementation details
2. Review [DESIGN.md](./DESIGN.md) for architecture
3. Run tests to verify your changes: `uv run pytest tests/`
4. Maintain 85%+ test coverage for new code

## License

Proprietary - Cybersecify

---

**Built by**: Cybersecify | **Author**: Rathnakara G N
**Last Updated**: November 26, 2025
**Status**: Production-ready | **Coverage**: 79%

