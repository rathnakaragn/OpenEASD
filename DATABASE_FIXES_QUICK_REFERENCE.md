# Database Layer - Quick Fix Reference

**Priority Fixes with Code Snippets**

---

## Fix 1: Add Foreign Key Constraints (CRITICAL)

### Finding Model
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/finding.py`

```python
from sqlmodel import Field, SQLModel

class Finding(SQLModel, table=True, extend_existing=True):
    """Security finding discovered during analysis."""

    __tablename__ = "findings"

    id: str = Field(primary_key=True, max_length=255)

    # ✅ ADD: Foreign key constraint
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    finding_type: str = Field(index=True, max_length=100)
    affected_asset: str = Field(index=True, max_length=255)
    # ... rest of fields
```

### CVEMapping Model
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/finding.py`

```python
class CVEMapping(SQLModel, table=True, extend_existing=True):
    """Maps findings to CVEs."""

    __tablename__ = "cve_mappings"

    id: str = Field(primary_key=True, max_length=255)

    # ✅ ADD: Foreign keys
    finding_id: str = Field(
        foreign_key="findings.id",
        index=True,
        max_length=255,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    vulnerability_id: str = Field(
        foreign_key="vulnerabilities.id",
        index=True,
        max_length=255,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    confidence: int = Field(default=50)
    # ... rest of fields
```

### SubdomainHistory Model
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/subdomain.py`

```python
from sqlmodel import Field, SQLModel
import uuid

class SubdomainHistory(SQLModel, table=True):
    """Subdomain history tracking."""

    __tablename__ = "subdomain_history"

    # ✅ CHANGE: Auto-generate UUID
    id: str = Field(
        primary_key=True,
        default_factory=lambda: str(uuid.uuid4())
    )

    # ✅ ADD: Foreign keys
    apex_domain: str = Field(
        foreign_key="domains.domain",
        max_length=255,
        index=True,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    subdomain: str = Field(max_length=255)

    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        max_length=255,
        index=True,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    status: str = Field(max_length=50, index=True)
    # ... rest of fields
```

### Tool Results (Apply to all 4 models)
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/tool_results.py`

```python
class SubfinderResult(SQLModel, table=True):
    """Subfinder scan results."""

    __tablename__ = "subfinder_results"

    # ✅ CHANGE: Auto-generate UUID
    id: str = Field(
        primary_key=True,
        default_factory=lambda: str(uuid.uuid4())
    )

    # ✅ ADD: Foreign key
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        max_length=255,
        index=True,
        sa_column_kwargs={"ondelete": "CASCADE"}
    )

    apex_domain: str = Field(max_length=255, index=True)
    subdomain: str = Field(max_length=255)
    # ... rest of fields

# Apply same pattern to AmassResult, NmapResult, NaabuResult
```

---

## Fix 2: Add Missing Indexes (CRITICAL)

### ScanSession Model
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/scan.py`

```python
from datetime import datetime
from sqlmodel import Field, SQLModel, Column, JSON

class ScanSession(SQLModel, table=True):
    """Scan session model for tracking security scans."""

    __tablename__ = "scan_sessions"

    scan_id: str = Field(primary_key=True, max_length=255)

    # ✅ ADD: Indexes
    scan_type: str = Field(max_length=100, index=True)
    tool_name: Optional[str] = Field(default=None, max_length=100, index=True)
    domains_scanned: Optional[str] = Field(default=None, sa_column=Column(JSON))

    # ✅ ADD: Index on start_time
    start_time: datetime = Field(default_factory=datetime.utcnow, index=True)
    end_time: Optional[datetime] = None

    # ✅ ADD: Index on status
    status: str = Field(default="queued", max_length=50, index=True)
    findings_count: int = Field(default=0)
```

### Domain Model
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/domain.py`

```python
class Domain(SQLModel, table=True):
    """Domain model for tracking monitored domains."""

    __tablename__ = "domains"

    domain: str = Field(primary_key=True, max_length=255)

    # ✅ ADD: Index on is_primary
    is_primary: bool = Field(default=False, index=True)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # ✅ ADD: Index on last_scanned_at
    last_scanned_at: Optional[datetime] = Field(default=None, index=True)

    scan_count: int = Field(default=0)
    contact_email: Optional[str] = Field(default=None, max_length=255)
    scan_frequency: Optional[str] = Field(default=None, max_length=50)
    active_scan_enabled: bool = Field(default=True)
```

---

## Fix 3: Fix Timezone Inconsistency (CRITICAL)

### SQLModelManager - API Key Update
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/database/sqlmodel_manager.py`

**Line 1635** - Fix inconsistent UTC call:

```python
# ❌ BEFORE:
from datetime import datetime
api_key.last_used_at = datetime.utcnow()

# ✅ AFTER:
from datetime import datetime, timezone
api_key.last_used_at = datetime.now(timezone.utc)
```

### Standardize All Model Defaults (Recommended)

**All Model Files**: Change from `datetime.utcnow` to `datetime.now(timezone.utc)`

```python
# ❌ BEFORE:
from datetime import datetime
created_at: datetime = Field(default_factory=datetime.utcnow)

# ✅ AFTER:
from datetime import datetime, timezone
created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```

**Note**: `datetime.utcnow()` is deprecated in Python 3.12+ and returns naive datetime.

---

## Fix 4: Add Metrics Caching (HIGH PRIORITY)

### SQLModelManager - Cache System Metrics
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/database/sqlmodel_manager.py`

**Add to __init__** (after line 67):

```python
def __init__(self, db_path: Optional[str] = None):
    # ... existing initialization ...

    # ✅ ADD: Metrics cache
    self._metrics_cache: Optional[Dict[str, Any]] = None
    self._metrics_cache_time: Optional[datetime] = None
    self._metrics_cache_ttl = 300  # 5 minutes in seconds
```

**Update get_system_metrics()** (line 1064):

```python
def get_system_metrics(self) -> Dict[str, Any]:
    """
    Get system metrics with 5-minute caching.

    Returns:
        Dictionary with system metrics
    """
    from datetime import timezone, timedelta

    now = datetime.now(timezone.utc)

    # ✅ ADD: Return cached metrics if still fresh
    if self._metrics_cache is not None and self._metrics_cache_time is not None:
        age = (now - self._metrics_cache_time).total_seconds()
        if age < self._metrics_cache_ttl:
            return self._metrics_cache

    # Calculate fresh metrics (existing code continues)
    with Session(self.engine) as session:
        metrics = {}

        # Domain metrics
        metrics['total_domains'] = session.exec(
            select(func.count()).select_from(Domain)
        ).one()
        # ... rest of existing metric calculations ...

    # ✅ ADD: Cache the results
    self._metrics_cache = metrics
    self._metrics_cache_time = now

    return metrics
```

---

## Fix 5: Add SQLAlchemy Relationships (MEDIUM PRIORITY)

### ScanSession Model - Add Relationships
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/scan.py`

```python
from sqlmodel import Field, SQLModel, Relationship, Column, JSON
from typing import List, Optional, TYPE_CHECKING

# ✅ ADD: Type checking imports
if TYPE_CHECKING:
    from .finding import Finding
    from .subdomain import SubdomainHistory

class ScanSession(SQLModel, table=True):
    """Scan session model for tracking security scans."""

    __tablename__ = "scan_sessions"

    scan_id: str = Field(primary_key=True, max_length=255)
    scan_type: str = Field(max_length=100, index=True)
    # ... rest of fields

    # ✅ ADD: Relationships
    findings: List["Finding"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={
            "lazy": "selectinload",
            "cascade": "all, delete-orphan"
        }
    )

    subdomain_history: List["SubdomainHistory"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={
            "lazy": "selectinload",
            "cascade": "all, delete-orphan"
        }
    )
```

### Finding Model - Add Reverse Relationship
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/finding.py`

```python
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from .scan import ScanSession
    from .cve_mapping import CVEMapping

class Finding(SQLModel, table=True, extend_existing=True):
    """Security finding discovered during analysis."""

    __tablename__ = "findings"

    id: str = Field(primary_key=True, max_length=255)
    scan_id: str = Field(
        foreign_key="scan_sessions.scan_id",
        index=True,
        max_length=255
    )
    # ... rest of fields

    # ✅ ADD: Relationships
    scan: Optional["ScanSession"] = Relationship(back_populates="findings")

    cve_mappings: List["CVEMapping"] = Relationship(
        back_populates="finding",
        sa_relationship_kwargs={
            "lazy": "selectinload",
            "cascade": "all, delete-orphan"
        }
    )
```

### Usage Example in Manager

```python
from sqlalchemy.orm import selectinload

def get_scan_with_findings(self, scan_id: str) -> Optional[Dict[str, Any]]:
    """Get scan with all findings in one query (no N+1)."""
    with Session(self.engine) as session:
        # ✅ Efficient: Single query with subquery for findings
        scan = session.exec(
            select(ScanSession)
            .where(ScanSession.scan_id == scan_id)
            .options(selectinload(ScanSession.findings))
        ).first()

        if not scan:
            return None

        return {
            'scan_id': scan.scan_id,
            'status': scan.status,
            # ✅ Findings already loaded - no additional query
            'findings': [self._finding_to_dict(f) for f in scan.findings]
        }
```

---

## Fix 6: Add Enum Constraints (MEDIUM PRIORITY)

### Finding Model - Severity and Status Enums
**File**: `/Users/rathnakara/projects/OpenEASD/src/data/models/finding.py`

```python
from enum import Enum
from sqlmodel import Field, SQLModel

# ✅ ADD: Enum definitions
class SeverityLevel(str, Enum):
    """Valid severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, Enum):
    """Valid status values for findings."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class Finding(SQLModel, table=True, extend_existing=True):
    """Security finding discovered during analysis."""

    __tablename__ = "findings"

    # ... existing fields ...

    # ✅ CHANGE: Use enum types
    severity: SeverityLevel = Field(index=True)
    status: FindingStatus = Field(default=FindingStatus.OPEN, max_length=20)

    # ... rest of fields
```

**Benefits**:
- Type-safe (IDE autocomplete)
- Validation at Python level
- Self-documenting code
- Can't insert invalid values

---

## Testing the Changes

### Run Migration Check
```bash
# Check if models can be created
uv run python -c "from src.data.models import *; from sqlmodel import create_engine, SQLModel; engine = create_engine('sqlite:///test.db'); SQLModel.metadata.create_all(engine)"
```

### Run Database Tests
```bash
# All tests should pass
uv run pytest tests/test_database_manager.py -v

# Run finding model tests
uv run pytest tests/test_finding_models.py -v
```

### Check for Orphaned Records
```bash
# After adding foreign keys, this should find issues
uv run python -c "
from src.data.database.sqlmodel_manager import SQLModelManager
db = SQLModelManager()

# Check for findings with invalid scan_ids
from sqlmodel import Session, select
from src.data.models.finding import Finding
from src.data.models.scan import ScanSession

with Session(db.engine) as session:
    findings = session.exec(select(Finding)).all()
    for f in findings:
        scan = session.get(ScanSession, f.scan_id)
        if not scan:
            print(f'Orphaned finding: {f.id} (scan_id: {f.scan_id})')
"
```

---

## Migration Strategy

### Phase 1: Non-Breaking (Deploy Immediately)
1. ✅ Add indexes (domains, scan_sessions, subdomain_history)
2. ✅ Fix timezone inconsistency (line 1635)
3. ✅ Add metrics caching
4. ✅ Standardize datetime imports

### Phase 2: Schema Changes (Requires Database Rebuild)
1. ✅ Add foreign key constraints
2. ✅ Add relationships
3. ✅ Change to enum types
4. ✅ Update UUID generation

**Note**: SQLite doesn't support ALTER TABLE for foreign keys, so a full database recreation is needed.

### Migration Script Template

```python
"""
Database migration: Add foreign keys and indexes
"""
from sqlmodel import create_engine, SQLModel
from src.data.models import *
from src.data.database.sqlmodel_manager import SQLModelManager
import shutil
from pathlib import Path

def migrate():
    db_path = Path("data/openeasd.sqlite")
    backup_path = db_path.with_suffix(".backup")

    # 1. Backup existing database
    print("Creating backup...")
    shutil.copy(db_path, backup_path)

    # 2. Export data
    print("Exporting data...")
    old_db = SQLModelManager(str(db_path))
    data = export_all_data(old_db)
    old_db.close()

    # 3. Delete old database
    print("Removing old database...")
    db_path.unlink()

    # 4. Create new database with updated schema
    print("Creating new database with foreign keys...")
    new_db = SQLModelManager(str(db_path))
    new_db.initialize()

    # 5. Import data
    print("Importing data...")
    import_all_data(new_db, data)
    new_db.close()

    print("Migration complete! Backup saved to:", backup_path)

if __name__ == "__main__":
    migrate()
```

---

## Quick Verification Checklist

After applying fixes:

- [ ] All 30 database tests pass
- [ ] Foreign key constraints are enforced (test orphaned record insertion)
- [ ] Indexes are created (check with EXPLAIN QUERY PLAN)
- [ ] Timezone handling is consistent (all UTC storage)
- [ ] Metrics caching works (verify with timing tests)
- [ ] Relationships load correctly (test eager loading)
- [ ] Enum validation works (test invalid severity insertion)

---

**End of Quick Reference**

For detailed analysis, see: `/Users/rathnakara/projects/OpenEASD/DATABASE_LAYER_REVIEW.md`
