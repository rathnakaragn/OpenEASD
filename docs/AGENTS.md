# Claude Agents for OpenEASD

This document describes the 9 specialized Claude agents configured for OpenEASD development, their responsibilities, optimal use cases, and how to choose the right agent for your task.

## Overview

OpenEASD uses a tiered agent system with Claude models optimized for different types of tasks:

| Tier | Model | Count | Purpose |
|------|-------|-------|---------|
| **Tier 1** | 🔴 Opus | 4 | Complex reasoning, architectural decisions |
| **Tier 2** | 🟢 Sonnet | 4 | Balanced performance, layer implementation |
| **Tier 3** | 🟡 Haiku | 1 | Fast validation, QA checks |

## Agent Tier 1: Opus (Complex Reasoning)

Use Opus agents for tasks requiring deep architectural reasoning and sophisticated analysis.

### 1. design-reviewer
**Location**: `.claude/agents/design-reviewer.md`

**Responsibility**: Validate architectural decisions against the 6-layer OpenEASD model

**Use When**:
- Reviewing API endpoint placement and design
- Validating service layer patterns
- Assessing cross-layer interactions
- Ensuring security model alignment
- Making major architectural decisions

**Example Usage**:
```
"Review this new findings endpoint - does it fit our 6-layer architecture?"
```

**Speed**: 10-20 seconds | **Cost**: High

---

### 2. layer-architect ⬆️ UPGRADED TO OPUS
**Location**: `.claude/agents/layer-architect.md`

**Responsibility**: Design and implement features across any layer of the 6-layer architecture

**Use When**:
- Adding new features spanning multiple layers
- Refactoring layer interactions
- Debugging complex cross-layer issues
- Making significant layer-specific changes
- Designing new layer components

**Example Usage**:
```
"I need to add a new detector for exposed APIs - how should I structure it?"
```

**Speed**: 10-20 seconds | **Cost**: High

---

### 3. layer4-analysis-agent ⬆️ UPGRADED TO OPUS
**Location**: `.claude/agents/layer4-analysis-agent.md`

**Responsibility**: Develop vulnerability detection, risk scoring, and finding management

**Use When**:
- Designing new vulnerability detectors
- Implementing risk scoring algorithms
- Adding CVE mapping capabilities
- Improving finding deduplication logic
- Enhancing analysis features

**Example Usage**:
```
"How should I implement SSL certificate vulnerability detection with proper risk scoring?"
```

**Speed**: 10-20 seconds | **Cost**: High

---

### 4. layer6-database-architect ⬆️ UPGRADED TO OPUS
**Location**: `.claude/agents/layer6-database-architect.md`

**Responsibility**: Database schema design and query optimization

**Use When**:
- Designing new database tables or schemas
- Optimizing slow queries
- Implementing complex relationships
- Handling timezone conversions (IST)
- Managing data integrity constraints

**Example Usage**:
```
"The scan results query is getting slow. How should I optimize it?"
```

**Speed**: 10-20 seconds | **Cost**: High

---

## Agent Tier 2: Sonnet (Balanced Performance)

Use Sonnet agents for layer-specific implementation with well-established patterns.

### 5. api-layer-builder
**Location**: `.claude/agents/api-layer-builder.md`

**Responsibility**: Create and review API endpoints (read-only GET operations)

**Use When**:
- Adding new API endpoints
- Designing Pydantic schemas
- Implementing request/response validation
- Adding error handling to endpoints
- Extending OpenAPI documentation

**Example Usage**:
```
"Create a GET endpoint for scan statistics with pagination"
```

**Speed**: 5-10 seconds | **Cost**: Medium

---

### 6. layer3-cli-architect
**Location**: `.claude/agents/layer3-cli-architect.md`

**Responsibility**: Design and implement CLI commands

**Use When**:
- Creating new CLI commands
- Designing command structure
- Implementing user interactions
- Formatting output (table/json/csv)
- Adding help text and documentation

**Example Usage**:
```
"Design a new batch domain management command with --filter options"
```

**Speed**: 5-10 seconds | **Cost**: Medium

---

### 7. layer5-tools-executor
**Location**: `.claude/agents/layer5-tools-executor.md`

**Responsibility**: Implement security tool integration and execution

**Use When**:
- Adding new security tool support
- Implementing subprocess execution
- Parsing tool JSON output
- Managing timeouts
- Handling tool errors

**Example Usage**:
```
"Add httpx tool integration for HTTP probing"
```

**Speed**: 5-10 seconds | **Cost**: Medium

---

### 8. service-layer-architect
**Location**: `.claude/agents/service-layer-architect.md`

**Responsibility**: Design business logic and service methods

**Use When**:
- Creating new service methods
- Implementing CRUD operations
- Designing service orchestration
- Refactoring duplicated logic
- Improving testability

**Example Usage**:
```
"Design a method to group findings by vulnerability type and severity"
```

**Speed**: 5-10 seconds | **Cost**: Medium

---

## Agent Tier 3: Haiku (Fast Validation)

Use Haiku for rapid, pattern-based validation suitable for pre-commit hooks and CI/CD.

### 9. qa-reviewer ✨ NEW
**Location**: `.claude/agents/qa-reviewer.md`

**Responsibility**: Validate code quality, test coverage, and pattern compliance

**Use When**:
- Checking code follows OpenEASD patterns
- Validating test coverage (85%+ threshold)
- Verifying error handling
- Confirming documentation presence
- Running pre-commit validation
- Quick code review checks

**Example Usage**:
```
"Check if this service method follows OpenEASD patterns"
```

**Features**:
- ✅ Code style validation (naming, line length, imports)
- ✅ Test coverage verification (85%+ minimum)
- ✅ Pattern compliance checking (all 6 layers)
- ✅ Documentation verification (docstrings, type hints)
- ✅ Error handling validation
- ✅ Layer boundary compliance

**Speed**: 2-5 seconds | **Cost**: Very Low (~$0.01 per check)

**Perfect For**:
- Pre-commit hooks
- CI/CD pipeline validation
- Rapid feedback loops
- Per-file validation

---

## How to Choose the Right Agent

### Decision Flowchart

```
"I need help with..."

├─→ "...validating code quality/patterns"
│   → qa-reviewer (🟡 Haiku) - 2-5 seconds

├─→ "...creating an API endpoint"
│   → api-layer-builder (🟢 Sonnet) - 5-10s

├─→ "...creating a CLI command"
│   → layer3-cli-architect (🟢 Sonnet) - 5-10s

├─→ "...adding business logic/service"
│   → service-layer-architect (🟢 Sonnet) - 5-10s

├─→ "...implementing a security tool"
│   → layer5-tools-executor (🟢 Sonnet) - 5-10s

├─→ "...vulnerability detection/risk scoring"
│   → layer4-analysis-agent (🔴 Opus) - 10-20s

├─→ "...database schema/query optimization"
│   → layer6-database-architect (🔴 Opus) - 10-20s

├─→ "...cross-layer design/refactoring"
│   → layer-architect (🔴 Opus) - 10-20s

└─→ "...architectural/design validation"
    → design-reviewer (🔴 Opus) - 10-20s
```

### Quick Reference Matrix

| Need | Agent | Model | Speed |
|------|-------|-------|-------|
| **Code Quality Check** | qa-reviewer | 🟡 Haiku | ⚡ 2-5s |
| **API Endpoint** | api-layer-builder | 🟢 Sonnet | ⚡⚡ 5-10s |
| **CLI Command** | layer3-cli-architect | 🟢 Sonnet | ⚡⚡ 5-10s |
| **Service Method** | service-layer-architect | 🟢 Sonnet | ⚡⚡ 5-10s |
| **Tool Integration** | layer5-tools-executor | 🟢 Sonnet | ⚡⚡ 5-10s |
| **Detector/Scoring** | layer4-analysis-agent | 🔴 Opus | ⚡⚡⚡ 10-20s |
| **Database/Query** | layer6-database-architect | 🔴 Opus | ⚡⚡⚡ 10-20s |
| **Layer Design** | layer-architect | 🔴 Opus | ⚡⚡⚡ 10-20s |
| **Architecture** | design-reviewer | 🔴 Opus | ⚡⚡⚡ 10-20s |

---

## Example Workflows

### Workflow 1: Adding a New API Endpoint
1. **design-reviewer** (Opus) - Validate endpoint design and layer placement
2. **api-layer-builder** (Sonnet) - Implement the endpoint
3. **qa-reviewer** (Haiku) - Validate code quality and test coverage

### Workflow 2: Optimizing Database Performance
1. **layer6-database-architect** (Opus) - Analyze and optimize queries
2. **qa-reviewer** (Haiku) - Verify changes don't break patterns

### Workflow 3: Implementing New Vulnerability Detection
1. **layer4-analysis-agent** (Opus) - Design detector and scoring
2. **layer6-database-architect** (Opus) - Schema updates if needed
3. **qa-reviewer** (Haiku) - Validate code quality and coverage

### Workflow 4: Adding a New CLI Command
1. **layer3-cli-architect** (Sonnet) - Design command structure
2. **service-layer-architect** (Sonnet) - Implement service methods if needed
3. **qa-reviewer** (Haiku) - Final validation

### Workflow 5: Pre-Commit Validation (Fast Path)
→ **qa-reviewer** (Haiku) - Quick pattern and coverage checks
  If issues found: Use appropriate specialist agent

---

## Configuration Details

### File Locations
All agent configurations stored in: `.claude/agents/`

```
.claude/agents/
├── api-layer-builder.md           (🟢 Sonnet, 10 KB)
├── design-reviewer.md             (🔴 Opus, 10 KB)
├── layer-architect.md             (🔴 Opus, 12 KB) ⬆️
├── layer3-cli-architect.md        (🟢 Sonnet, 8 KB)
├── layer4-analysis-agent.md       (🔴 Opus, 12 KB) ⬆️
├── layer5-tools-executor.md       (🟢 Sonnet, 13 KB)
├── layer6-database-architect.md   (🔴 Opus, 9 KB) ⬆️
├── service-layer-architect.md     (🟢 Sonnet, 15 KB)
└── qa-reviewer.md                 (🟡 Haiku, 15 KB) ✨
```

### Model Distribution
- **Opus**: 4 agents (complex reasoning, architecture, algorithms, optimization)
- **Sonnet**: 4 agents (layer implementation with balanced performance)
- **Haiku**: 1 agent (fast validation suitable for pre-commit and CI/CD)

---

## Layer Coverage

Each layer of the 6-layer architecture has dedicated agent support:

| Layer | Primary Agent | Secondary Agent(s) |
|-------|---------------|-------------------|
| **Layer 1: API** | api-layer-builder (Sonnet) | design-reviewer (Opus) |
| **Layer 2: Service** | service-layer-architect (Sonnet) | layer-architect (Opus) |
| **Layer 3: CLI** | layer3-cli-architect (Sonnet) | layer-architect (Opus) |
| **Layer 4: Analysis** | layer4-analysis-agent (Opus) | layer-architect (Opus) |
| **Layer 5: Tools** | layer5-tools-executor (Sonnet) | layer-architect (Opus) |
| **Layer 6: Database** | layer6-database-architect (Opus) | layer-architect (Opus) |
| **Cross-Layer** | layer-architect (Opus) | design-reviewer (Opus) |
| **Quality Assurance** | qa-reviewer (Haiku) | All other agents (escalation) |

---

## Cost-Performance Profile

### Speed Comparison
```
Haiku:    ⚡⚡⚡ 2-5 seconds   (Fastest)
Sonnet:   ⚡⚡  5-10 seconds
Opus:     ⚡   10-20 seconds  (Slowest but most capable)
```

### Cost Comparison (Relative)
```
Haiku:    $ ~$0.01 per check  (Cheapest)
Sonnet:   $$ ~$0.05 per check
Opus:     $$$ ~$0.20 per check (Most expensive)
```

### Use Cases by Model
- **Haiku**: QA validation, pre-commit checks, rapid feedback (100+ checks/day)
- **Sonnet**: Layer implementation, code generation, balanced tasks (20-50 per day)
- **Opus**: Complex reasoning, architecture, algorithms (5-10 per day)

---

## Best Practices

### 1. Start with Quick Checks
Use qa-reviewer first for fast feedback, then escalate to specialists:
```
User: "Review my new service method"
→ qa-reviewer (2-5s) validates patterns, coverage, documentation
→ If architectural: service-layer-architect (Sonnet) or layer-architect (Opus)
```

### 2. Choose by Complexity
- **Simple/straightforward**: Use Sonnet agents
- **Complex/algorithmic**: Use Opus agents
- **QA/validation**: Always use qa-reviewer

### 3. Leverage Workflows
Use multi-agent workflows for major features:
```
Feature: "Add new API endpoint for findings statistics"
1. design-reviewer validates architecture (Opus)
2. api-layer-builder implements (Sonnet)
3. qa-reviewer validates code quality (Haiku)
```

### 4. Pre-Commit Integration
Use qa-reviewer in git hooks:
```bash
# Validate code before commit
claude-code qa-reviewer --files <changed-files>
# FAIL blocks commit, WARN is informational
```

### 5. CI/CD Pipeline
Run qa-reviewer in pull request checks:
```yaml
- name: Code Quality Check
  run: claude-code qa-reviewer --files ${{ github.event.pull_request.files }}
```

---

## Agent Capabilities by Layer

### API Layer (Layer 1)
- **Primary**: api-layer-builder (Sonnet)
  - Endpoint design and implementation
  - Pydantic schema validation
  - Error handling

- **Secondary**: design-reviewer (Opus)
  - Architectural validation
  - Security model alignment

### Service Layer (Layer 2)
- **Primary**: service-layer-architect (Sonnet)
  - Service method design
  - Business logic implementation
  - CRUD operations

- **Secondary**: layer-architect (Opus)
  - Cross-service patterns
  - Orchestration design

### CLI Layer (Layer 3)
- **Primary**: layer3-cli-architect (Sonnet)
  - Command design
  - User interaction
  - Output formatting

- **Secondary**: layer-architect (Opus)
  - Complex command workflows

### Analysis Layer (Layer 4)
- **Primary**: layer4-analysis-agent (Opus)
  - Detector design
  - Risk scoring algorithms
  - Finding management

- **Secondary**: layer-architect (Opus)
  - Integration with other layers

### Tools Layer (Layer 5)
- **Primary**: layer5-tools-executor (Sonnet)
  - Tool integration
  - Subprocess execution
  - JSON parsing

- **Secondary**: layer-architect (Opus)
  - Tool orchestration

### Database Layer (Layer 6)
- **Primary**: layer6-database-architect (Opus)
  - Schema design
  - Query optimization
  - Relationship modeling

- **Secondary**: layer-architect (Opus)
  - Cross-layer data flow

---

## QA Agent Special Use Cases

The qa-reviewer agent provides specialized validation for all layers:

### Tier 1 Checks (Fast)
✓ Code style (naming, line length, imports)
✓ Test coverage verification (85%+ threshold)
✓ Pattern compliance
✓ Documentation presence
✓ Import organization
✓ Type hints presence

### Tier 2 Checks (Moderate)
✓ Pydantic schema validation
✓ Click command patterns
✓ API endpoint structure
✓ Database model relationships
✓ Service layer patterns
✓ Test file structure

### Tier 3 Checks (Escalate)
⚠ Performance optimization
⚠ Architectural impact
⚠ Cross-layer dependencies
⚠ Complex security issues

---

## FAQ

### Q: When should I use Haiku vs Sonnet vs Opus?
**A**: Use Haiku for QA/validation (fast feedback), Sonnet for layer implementation (balanced), Opus for complex reasoning (architecture/algorithms).

### Q: Can I use multiple agents for one task?
**A**: Yes! Use multi-agent workflows for major features. Start with design-reviewer (architecture), then implement with layer-specific agent (Sonnet), then validate with qa-reviewer (Haiku).

### Q: How much does each agent cost?
**A**: Haiku (~$0.01), Sonnet (~$0.05), Opus (~$0.20) per typical check. Haiku is ideal for frequent checks.

### Q: What if the agent suggests using another agent?
**A**: This is intentional! Agents escalate to specialists. Follow the recommendation and use the suggested agent.

### Q: Can I use qa-reviewer for architectural decisions?
**A**: No, qa-reviewer is for pattern validation only. Use design-reviewer or layer-architect for architectural decisions.

### Q: How do I integrate agents into CI/CD?
**A**: Use qa-reviewer in pull request checks. Add escalation paths to Sonnet/Opus agents for complex issues.

---

## Recent Updates

### December 2, 2025
- ✅ Created qa-reviewer agent (Haiku model)
- ✅ Upgraded layer-architect to Opus
- ✅ Upgraded layer4-analysis-agent to Opus
- ✅ Upgraded layer6-database-architect to Opus
- ✅ Final configuration: 4 Opus + 4 Sonnet + 1 Haiku
- ✅ All agents aligned with 6-layer architecture
- ✅ Removed all 7-layer/Messaging Layer references

---

**Last Updated**: December 2, 2025
**Status**: All agents configured and optimized
**Total Agents**: 9 (4 Opus + 4 Sonnet + 1 Haiku)
