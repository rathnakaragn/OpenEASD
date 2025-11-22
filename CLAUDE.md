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
  - Contains: 5-layer architecture diagram, technology stack, design principles

### Layer Documentation
- **[docs/00-CLI.md](./docs/00-CLI.md)** - CLI Layer implementation guide
  - Target audience: CLI Developers, DevOps Engineers
  - Contains: Commands, formatters, output formats, user interface

- **[docs/01-RECON.md](./docs/01-RECON.md)** - Recon Layer implementation guide
  - Target audience: Security Engineers, Tool Developers
  - Contains: Security tool modules, data collection, parsing logic

- **[docs/02-ANALYSIS.md](./docs/02-ANALYSIS.md)** - Analysis Layer implementation guide
  - Target audience: Security Analysts, Detection Engineers
  - Contains: Vulnerability detection, risk scoring, analysis engines

- **[docs/03-NOTIFICATION.md](./docs/03-NOTIFICATION.md)** - Notification Layer implementation guide
  - Target audience: Integration Engineers, DevOps Engineers
  - Contains: Alert generation, multi-channel routing, templates

- **[docs/04-DATABASE.md](./docs/04-DATABASE.md)** - Database Layer implementation guide
  - Target audience: Database Engineers, Analytics Engineers
  - Contains: Schema design, query patterns, DuckDB optimization

## Quick Reference

### Current Implementation Status
- **Architecture**: 5-layer design (CLI → Recon → Analysis → Notification → Database)
- **Implementation**: 3 layers complete (CLI, Recon, Database), 2 layers planned (Analysis, Notification)
- **Tech Stack**: Click CLI, Python Asyncio, DuckDB, Security Tools
- **Security Tools**: Subfinder, Amass, Nmap, Naabu (subprocess execution)
- **Status**: Production-ready CLI with planned expansion

### 5-Layer Architecture

1. **CLI Layer** ✅ - User interface and command handling
2. **Recon Layer** ✅ - Data collection and tool execution
3. **Analysis Layer** ⏳ - Security analysis and vulnerability detection (Planned)
4. **Notification Layer** ⏳ - Alert generation and notification routing (Planned)
5. **Database Layer** ✅ - Data persistence and analytics

## Implementation Progress

| Layer | Status | Progress | Priority |
|-------|--------|----------|----------|
| CLI Layer | ✅ Complete | 100% | - |
| Recon Layer | ✅ Complete | 100% | - |
| Analysis Layer | ⏳ Planned | 0% | Medium |
| Notification Layer | ⏳ Planned | 0% | Low |
| Database Layer | ✅ Complete | 100% | - |

## Key Implementation Notes

1. **5-layer separation** with single responsibility per layer
2. **Modular architecture** with interface-based design patterns
3. **Async-first** implementation using Python asyncio
4. **Security tools** in `src/recon/modules/{tool}/` with standardized interfaces
5. **Clean data flow**: CLI → Recon → Analysis → Notification → Database
6. **DuckDB analytics** for high-performance queries and reporting

## Current Features

### ✅ Implemented (Layers 1, 2, 5)

**CLI Layer**:
- Multiple commands: scan, history, results, delete, scans
- Output formats: table, json, csv, txt
- Organization-based domain grouping
- UUID-based scan tracking
- Interactive deletion with preview

**Recon Layer**:
- **Subfinder**: Passive subdomain discovery
- **Amass**: Comprehensive subdomain enumeration
- **Nmap**: Service detection and port scanning
- **Naabu**: Fast port scanning
- ReconTool interface for consistent tool integration

**Database Layer**:
- DuckDB storage engine
- Organization tracking
- Scan session management
- Timezone-aware timestamps (IST)
- Efficient querying and aggregation

### ⏳ Planned (Layers 3, 4)

**Analysis Layer** (Planned):
- Vulnerability detection
- Risk scoring
- Pattern recognition
- Threat classification

**Notification Layer** (Planned):
- Alert generation
- Multi-channel routing (Email, Slack, Webhooks)
- Severity filtering
- Template rendering

## Data Flow

### Current Flow (3 Layers)
```
CLI Layer (user command)
    ↓
Recon Layer (tool execution)
    ↓
Database Layer (storage)
    ↓
CLI Layer (results display)
```

### Future Flow (5 Layers)
```
CLI Layer (user command)
    ↓
Recon Layer (tool execution)
    ↓
Analysis Layer (vulnerability detection)
    ↓
Notification Layer (alerts)
    ↓
Database Layer (storage)
    ↓
CLI Layer (results display)
```

## For AI Assistants

When helping with this project:

### General Guidelines
- **Check layer docs**: Reference specific `docs/{layer}.md` for implementation details
- **Follow DESIGN.md**: For overall architecture and system design principles
- **Respect layer boundaries**: Keep layer responsibilities clean and focused
- **Use interfaces**: Follow abstract interface patterns defined in each layer
- **Maintain separation**: Don't mix layer concerns

### Current State Awareness
- **CLI Layer**: Fully functional, use as reference for user interaction patterns
- **Recon Layer**: All tools implemented, follow ReconTool interface for new tools
- **Database Layer**: DuckDB fully implemented, extend schema carefully
- **Analysis Layer**: Not implemented yet, plan carefully before starting
- **Notification Layer**: Not implemented yet, design integration points first

### File Organization
```
src/
├── cli/           # Layer 1 ✅ - Commands and formatters
├── recon/         # Layer 2 ✅ - Tool runners and parsers
├── analysis/      # Layer 3 ⏳ - To be implemented
├── notification/  # Layer 4 ⏳ - To be implemented
└── data/          # Layer 5 ✅ - DuckDB manager
```

### Common Tasks

**Adding a new recon tool**:
1. Create `src/recon/modules/{tool}/runner.py`
2. Implement `ReconTool` interface
3. Add to module `__init__.py`
4. Update `docs/01-RECON.md`

**Adding a new CLI command**:
1. Add Click command in `src/cli/main.py`
2. Implement logic in `src/cli/commands.py`
3. Add formatter support in `src/cli/formatters.py`
4. Update `docs/00-CLI.md`

**Database schema changes**:
1. Review `src/data/database/duckdb_manager.py`
2. Test schema changes carefully
3. Consider migration strategy
4. Update `docs/04-DATABASE.md`

## Technology Stack

### Implemented Layers
- **CLI**: Click 8.1.7, Python 3.11+
- **Recon**: Subprocess, Asyncio, JSON/XML parsing
- **Database**: DuckDB 1.4.1, SQL

### Tool Dependencies
- **Subfinder**: https://github.com/projectdiscovery/subfinder
- **Amass**: https://github.com/owasp-amass/amass
- **Nmap**: https://nmap.org/
- **Naabu**: https://github.com/projectdiscovery/naabu

### Planned Layers
- **Analysis**: Python, Pattern Matching, ML libraries (future)
- **Notification**: Email (SMTP), Slack API, Webhooks

## Best Practices

1. **Layer Isolation**: Never bypass layers in data flow
2. **Interface Contracts**: Always implement defined interfaces
3. **Error Handling**: Use proper try/except and logging
4. **Async Patterns**: Use `async/await` for I/O operations
5. **Testing**: Write tests for each layer independently
6. **Documentation**: Update layer docs when adding features

## Quick Start for Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run a scan
python openeasd.py scan example.com --org "Example"

# View history
python openeasd.py history

# View results
python openeasd.py results <scan-id>

# List all scans
python openeasd.py scans
```

## Architecture Evolution

### Version History
- **v6.0** (October 2025): 5-layer architecture, 3 implemented + 2 planned
- **v5.0** (January 2025): 4-layer simplified design (outdated)
- **Earlier**: 6-layer design with API/Scheduler (outdated)

### Current Focus
- ✅ Stabilize CLI, Recon, Database layers
- ⏳ Plan Analysis layer implementation
- ⏳ Design Notification layer integration

---

*This guide helps AI assistants understand the project structure. For detailed information, refer to the specific documents listed above.*

**Last Updated**: October 2025
**Architecture Version**: 5-Layer (3 Implemented, 2 Planned)
