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
- **Architecture**: 3-layer design (CLI → Tools → Database)
- **Model**: Single-organization architecture (simplified from multi-org)
- **Tech Stack**: Click CLI, Python 3.11+, DuckDB, Subprocess
- **Security Tools**: Subfinder, Amass, Nmap, Naabu (direct subprocess execution)
- **Status**: Production-ready with full CLI and database functionality

### 3-Layer Architecture

1. **CLI Layer** ✅ - User interface, commands, and tool orchestration
2. **Tools Layer** ✅ - Security tool execution (Subfinder, Amass, Nmap, Naabu)
3. **Database Layer** ✅ - Data persistence and analytics (DuckDB)

## Implementation Progress

| Layer | Status | Progress | Notes |
|-------|--------|----------|-------|
| CLI Layer | ✅ Complete | 100% | Scan & domain commands, batch operations |
| Tools Layer | ✅ Complete | 100% | Direct subprocess calls, JSON parsing |
| Database Layer | ✅ Complete | 100% | Single-org model, IST timezone support |

## Key Implementation Notes

1. **3-layer separation** with clear responsibilities
2. **Single organization** model (no multi-tenancy)
3. **Direct tool execution** via subprocess (no orchestration layer)
4. **Security tools** in `src/tools/{tool}/` modules
5. **Simple data flow**: CLI → Tools → Database → CLI
6. **DuckDB analytics** for efficient querying and aggregations
7. **IST timezone** support for all timestamps

## Current Features

### ✅ Fully Implemented (All 3 Layers)

**CLI Layer**:
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

### 3-Layer Workflow

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
│ Tools Layer                  │
│ - Execute subfinder          │
│ - Parse JSON output          │
│ - Return subdomains list     │
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
- **Single organization**: No multi-tenancy complexity
- **Direct tool execution**: Tools called via subprocess, no orchestration layer
- **Simple data flow**: CLI → Tools → Database → CLI

### Current State Awareness
- **CLI Layer**: Production-ready with all commands implemented
- **Tools Layer**: Subfinder actively used, other tools available as modules
- **Database Layer**: DuckDB fully implemented with single-org schema
- **No orchestration layer**: Tools are called directly from CLI commands

### File Organization
```
src/
├── cli/           # Layer 1 ✅ - Commands, formatters, tool orchestration
│   ├── main.py
│   ├── commands.py
│   ├── commands_domain.py
│   └── formatters.py
├── tools/         # Layer 2 ✅ - Security tool modules
│   ├── subfinder/
│   ├── amass/
│   ├── nmap/
│   └── naabu/
├── data/          # Layer 3 ✅ - DuckDB manager
│   └── database/
│       └── duckdb_manager.py
├── core/          # Core infrastructure
└── utils/         # Utilities (config, logging, timezone)
```

### Common Tasks

**Adding a new security tool**:
1. Create `src/tools/{tool}/` directory
2. Add `__init__.py` and `runner.py`
3. Implement subprocess execution and JSON parsing
4. Add CLI command in `src/cli/commands.py`
5. Test tool execution and data storage

**Adding a new CLI command**:
1. Add Click command in `src/cli/main.py`
2. Implement logic in `src/cli/commands.py` or `commands_domain.py`
3. Add formatter support in `src/cli/formatters.py`
4. Update DESIGN.md documentation

**Database schema changes**:
1. Review `src/data/database/duckdb_manager.py`
2. Update table creation in `_initialize_sync()`
3. Test schema changes carefully
4. Update DESIGN.md with schema documentation
5. **Note**: Avoid adding indexes on scan_sessions (DuckDB limitation)

## Technology Stack

### All Layers (Fully Implemented)
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
- Click 8.1.7 - CLI framework
- DuckDB 1.4.1 - Embedded database
- pytz - Timezone support (IST)
- PyYAML 6.0.1 - Configuration files
- pytest 8.2.2 - Testing framework (dev dependency)

## Best Practices

1. **Layer Separation**: CLI → Tools → Database → CLI
2. **Single Organization**: No multi-tenancy complexity
3. **Direct Execution**: Call tools via subprocess, no orchestration layer
4. **Error Handling**: Use proper try/except and logging
5. **Async Patterns**: Use `async/await` for database operations
6. **IST Timezone**: All timestamps in Indian Standard Time
7. **No scan_sessions indexes**: Avoid due to DuckDB UPDATE limitation

## Quick Start for Development

```bash
# Install dependencies using uv
uv sync

# Add a domain
uv run python openeasd.py domain add example.com --primary

# Run a single domain scan
uv run python openeasd.py scan domain example.com

# Run batch scan (all domains)
uv run python openeasd.py scan subfinder

# View domain list
uv run python openeasd.py domain list

# View scan history
uv run python openeasd.py history

# View all scans
uv run python openeasd.py scans

# View specific scan results
uv run python openeasd.py results <scan-id>
```

## Architecture Evolution

### Version History
- **v7.0** (November 2025): 3-layer architecture, single-organization, production-ready
- **v6.0** (October 2025): 5-layer architecture, 3 implemented + 2 planned (deprecated)
- **v5.0** (January 2025): 4-layer simplified design (deprecated)
- **Earlier**: 6-layer design with API/Scheduler (outdated)

### Current Focus
- ✅ Production-ready 3-layer architecture
- ✅ Single-organization model (simplified from multi-org)
- ✅ All core features implemented and tested
- ✅ Direct subprocess tool execution
- ✅ DuckDB with optimized queries

---

*This guide helps AI assistants understand the project structure. For detailed information, refer to DESIGN.md.*

**Last Updated**: November 2025
**Architecture Version**: 3-Layer (All Layers Complete)
**Package Manager**: uv (migrated from pip)

### Running Commands
- **With uv**: `uv run python openeasd.py <command>`
- **Direct python**: `/Users/rathnakara/projects/OpenEASD/.venv/bin/python openeasd.py <command>`