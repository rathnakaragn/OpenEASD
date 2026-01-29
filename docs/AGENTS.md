# Claude Agents for OpenEASD

This document describes the specialized Claude agents configured for OpenEASD development, their responsibilities, optimal use cases, and how to choose the right agent for your task.

## Overview

OpenEASD uses a collection of specialized agents for different development tasks:

| Agent | Purpose |
|-------|---------|
| **product-architect** | High-level product architecture decisions |
| **api-designer** | API endpoint design and REST patterns |
| **layer1-api-builder** | API layer implementation |
| **layer2-orchestrator-builder** | Orchestrator/service layer implementation |
| **layer4-tools-builder** | Security tool integration |
| **layer5-analysis-builder** | Analysis and detection implementation |
| **layer6-database-builder** | Database schema and queries |
| **frontend-agent** | Web dashboard development |
| **qa-agent** | Testing and quality assurance |
| **doc-agent** | Documentation maintenance |
| **code-cleaner** | Code cleanup and refactoring |

## Agent Descriptions

### 1. product-architect
**Location**: `.claude/agents/product-architect.md`

**Responsibility**: High-level product architecture and design decisions

**Use When**:
- Making major architectural decisions
- Evaluating new feature proposals
- Designing system-wide changes
- Reviewing technical approach

**Example Usage**:
```
"Should we add real-time notifications? What's the best approach?"
```

---

### 2. api-designer
**Location**: `.claude/agents/api-designer.md`

**Responsibility**: Design REST API endpoints and patterns

**Use When**:
- Designing new API endpoints
- Reviewing API consistency
- Defining request/response schemas
- Planning API versioning

**Example Usage**:
```
"Design the API endpoints for batch scan operations"
```

---

### 3. layer1-api-builder
**Location**: `.claude/agents/layer1-api-builder.md`

**Responsibility**: Implement Layer 1 (API) components

**Use When**:
- Adding new API endpoints
- Implementing Pydantic schemas
- Setting up route handlers
- Configuring FastAPI middleware

**Example Usage**:
```
"Implement the POST /api/v1/scans/batch endpoint"
```

---

### 4. layer2-orchestrator-builder
**Location**: `.claude/agents/layer2-orchestrator-builder.md`

**Responsibility**: Implement Layer 2 (Orchestrator) services

**Use When**:
- Creating service methods
- Implementing business logic
- Coordinating between layers
- Building workflow orchestration

**Example Usage**:
```
"Add a method to retry multiple failed scans at once"
```

---

### 5. layer4-tools-builder
**Location**: `.claude/agents/layer4-tools-builder.md`

**Responsibility**: Implement Layer 4 (Tools) integrations

**Use When**:
- Adding new security tool support
- Implementing subprocess execution
- Parsing tool JSON output
- Handling tool errors and timeouts

**Example Usage**:
```
"Integrate a new tool for SSL certificate analysis"
```

---

### 6. layer5-analysis-builder
**Location**: `.claude/agents/layer5-analysis-builder.md`

**Responsibility**: Implement Layer 5 (Analysis) components

**Use When**:
- Creating new vulnerability detectors
- Implementing risk scoring algorithms
- Adding CVE mapping capabilities
- Building finding deduplication logic

**Example Usage**:
```
"Create a detector for exposed database ports"
```

---

### 7. layer6-database-builder
**Location**: `.claude/agents/layer6-database-builder.md`

**Responsibility**: Implement Layer 6 (Database) components

**Use When**:
- Designing database schemas
- Creating SQLModel models
- Optimizing queries
- Managing migrations

**Example Usage**:
```
"Add a table to track scan scheduling"
```

---

### 8. frontend-agent
**Location**: `.claude/agents/frontend-agent.md`

**Responsibility**: Web dashboard development

**Use When**:
- Building dashboard UI components
- Implementing JavaScript functionality
- Styling with CSS
- Creating HTML templates

**Example Usage**:
```
"Add a chart showing findings by severity"
```

---

### 9. qa-agent
**Location**: `.claude/agents/qa-agent.md`

**Responsibility**: Testing and quality assurance

**Use When**:
- Writing unit tests
- Creating integration tests
- Reviewing test coverage
- Validating code quality

**Example Usage**:
```
"Write tests for the new batch scan endpoint"
```

---

### 10. doc-agent
**Location**: `.claude/agents/doc-agent.md`

**Responsibility**: Documentation maintenance

**Use When**:
- Updating CLAUDE.md after changes
- Keeping README.md current
- Documenting new features
- Maintaining architecture docs

**Example Usage**:
```
"Update documentation after adding the MCP server"
```

---

### 11. code-cleaner
**Location**: `.claude/agents/code-cleaner.md`

**Responsibility**: Code cleanup and refactoring

**Use When**:
- Removing dead code
- Refactoring for clarity
- Consolidating duplicated logic
- Improving code organization

**Example Usage**:
```
"Clean up unused imports in the orchestrator layer"
```

---

## How to Choose the Right Agent

### Decision Flowchart

```
"I need help with..."

+-> "...product/architecture decisions"
|   -> product-architect

+-> "...designing an API"
|   -> api-designer

+-> "...implementing an API endpoint"
|   -> layer1-api-builder

+-> "...business logic/services"
|   -> layer2-orchestrator-builder

+-> "...security tool integration"
|   -> layer4-tools-builder

+-> "...vulnerability detection/scoring"
|   -> layer5-analysis-builder

+-> "...database schema/queries"
|   -> layer6-database-builder

+-> "...web dashboard"
|   -> frontend-agent

+-> "...tests/quality"
|   -> qa-agent

+-> "...documentation"
|   -> doc-agent

+-> "...code cleanup"
    -> code-cleaner
```

### Quick Reference Matrix

| Need | Agent |
|------|-------|
| Architecture decisions | product-architect |
| API design | api-designer |
| API implementation | layer1-api-builder |
| Service/business logic | layer2-orchestrator-builder |
| Tool integration | layer4-tools-builder |
| Detectors/scoring | layer5-analysis-builder |
| Database/models | layer6-database-builder |
| Web UI | frontend-agent |
| Tests | qa-agent |
| Documentation | doc-agent |
| Refactoring | code-cleaner |

---

## Example Workflows

### Workflow 1: Adding a New API Endpoint
1. **api-designer** - Design endpoint (method, path, schemas)
2. **layer1-api-builder** - Implement the endpoint
3. **layer2-orchestrator-builder** - Implement service method
4. **qa-agent** - Write tests
5. **doc-agent** - Update documentation

### Workflow 2: Adding a New Security Tool
1. **product-architect** - Evaluate tool fit
2. **layer4-tools-builder** - Implement tool runner
3. **layer2-orchestrator-builder** - Add to workflow
4. **qa-agent** - Write tests
5. **doc-agent** - Document the tool

### Workflow 3: Adding a New Vulnerability Detector
1. **layer5-analysis-builder** - Implement detector
2. **layer6-database-builder** - Schema if needed
3. **qa-agent** - Write tests
4. **doc-agent** - Update docs

### Workflow 4: Building Dashboard Feature
1. **frontend-agent** - Implement UI
2. **layer1-api-builder** - Add API endpoints if needed
3. **qa-agent** - Test the feature

---

## Configuration Details

### File Locations
All agent configurations are stored in: `.claude/agents/`

```
.claude/agents/
├── api-designer.md
├── code-cleaner.md
├── doc-agent.md
├── frontend-agent.md
├── layer1-api-builder.md
├── layer2-orchestrator-builder.md
├── layer4-tools-builder.md
├── layer5-analysis-builder.md
├── layer6-database-builder.md
├── product-architect.md
└── qa-agent.md
```

---

## Layer Coverage

Each layer of the 6-layer architecture has dedicated agent support:

| Layer | Primary Agent | Purpose |
|-------|---------------|---------|
| **Layer 1: API** | layer1-api-builder | FastAPI endpoints |
| **Layer 2: Orchestrator** | layer2-orchestrator-builder | Business logic |
| **Layer 3: Job Queue** | layer6-database-builder | Job model, polling |
| **Layer 4: Tools** | layer4-tools-builder | Security tools |
| **Layer 5: Analysis** | layer5-analysis-builder | Detectors, scoring |
| **Layer 6: Database** | layer6-database-builder | Schema, queries |
| **Frontend** | frontend-agent | Web dashboard |
| **Cross-cutting** | product-architect | Architecture |
| **Quality** | qa-agent | Testing |
| **Documentation** | doc-agent | Docs |

---

## Current Architecture State

### Layer Responsibilities

| Layer | Key Files | Description |
|-------|-----------|-------------|
| **Layer 1: API** | `src/api/` | Full CRUD REST endpoints |
| **Layer 2: Orchestrator** | `src/orchestrator/` | Business logic services |
| **Layer 3: Job Queue** | `src/data/models/job.py` | Database-backed job queue |
| **Layer 4: Tools** | `src/tools/` | Security tool execution |
| **Layer 5: Analysis** | `src/analysis/` | Vulnerability detection |
| **Layer 6: Database** | `src/data/` | SQLModel + SQLite |
| **Frontend** | `src/frontend/` | Web dashboard |
| **MCP** | `src/mcp/` | Claude Code integration |

### Data Flow
```
API -> Orchestrator -> Database (Job)
                            |
                      Worker polls
                            |
                      Tools -> Analysis -> Database (Findings)
```

---

## FAQ

### Q: Which agent should I use for a cross-layer feature?
**A**: Start with product-architect to design the approach, then use layer-specific agents for implementation.

### Q: Can I use multiple agents for one task?
**A**: Yes! Complex features often require multiple agents in sequence.

### Q: What if I'm not sure which agent to use?
**A**: Start with product-architect for guidance on the best approach.

### Q: Where is the CLI agent?
**A**: OpenEASD is API-only - there is no CLI layer or CLI agent.

### Q: Where is the messaging/ZeroMQ agent?
**A**: The messaging layer was replaced with a database job queue. Use layer6-database-builder for job queue changes.

---

**Last Updated**: January 29, 2026
**Total Agents**: 11
**Architecture**: 6-Layer API-Only with Database Job Queue
