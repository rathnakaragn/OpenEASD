# Deprecated Models - Migration Complete

**Date**: November 26, 2025
**Status**: DEPRECATED - Do Not Use

## Files Deprecated

The following model files have been deprecated and their functionality moved to the Analysis Layer:

### 1. `src/data/models/alert.py` - SecurityAlert Model
**Status**: DEPRECATED
**Replaced By**: `src/analysis/models.py` → `Finding` model
**Reason**: Alerts are now managed as findings in the Analysis Layer for unified management with risk scoring

### 2. `src/data/models/finding.py` - Finding Models
**Status**: MOVED
**New Location**: `src/analysis/models.py`
**Reason**: Analysis layer models should be in the analysis layer, not data layer

## Migration Path

### Old Way (Deprecated)
```python
# ❌ DO NOT USE
from src.data.models.alert import SecurityAlert
from src.data.models.finding import Finding

# Create alert
alert = SecurityAlert(
    domain="example.com",
    vulnerability_type="open_port",
    severity="low"
)
```

### New Way (Correct)
```python
# ✅ USE THIS
from src.analysis import AlertManagementService
from src.analysis.models import Finding

# Create alert through analysis layer
alert_service = AlertManagementService(db_manager)
finding = alert_service.create_alert_from_scan(
    scan_id=scan_id,
    domain="example.com",
    vulnerability_type="open_port",
    severity="low",
    description="Open port detected",
    tool_source="naabu"
)
```

## Backward Compatibility

For temporary backward compatibility, you can still import from `src.data.models`:

```python
# This works but is deprecated
from src.data.models import Finding  # Re-exported from analysis layer

# Prefer direct import
from src.analysis.models import Finding  # Correct
```

## Database Changes

### Tables Affected

**security_alerts table**: DEPRECATED
- This table is no longer used
- All new alerts are stored in `findings` table
- Old data can remain for historical purposes
- Can be dropped with: `DROP TABLE IF EXISTS security_alerts;`

**findings table**: ACTIVE
- Now the single source of truth for all findings/alerts
- Contains risk scores, evidence, status tracking
- Managed by Analysis Layer

## What Changed

| Old System | New System |
|------------|------------|
| `SecurityAlert` model | `Finding` model |
| Simple alert with severity | Finding with risk score (0-100) |
| Stored in `security_alerts` table | Stored in `findings` table |
| Created directly in CLI/API | Created through `AlertManagementService` |
| No risk scoring | Deterministic risk scoring |
| Basic status (open) | Full lifecycle (open/acknowledged/resolved/false_positive) |

## Benefits of Migration

✅ **Unified Management**: Single model for all security findings
✅ **Risk Scoring**: Every finding gets a 0-100 risk score
✅ **Better Analysis**: Integrated with detectors and scoring engine
✅ **Status Tracking**: Full finding lifecycle management
✅ **Evidence**: Structured evidence and score breakdown
✅ **CVE Integration**: Findings can be linked to CVEs

## Files to Delete (After Backup)

Once you're confident the migration is complete:

```bash
# Optional: Create backup
cp src/data/models/alert.py src/data/models/alert.py.backup
cp src/data/models/finding.py src/data/models/finding.py.backup

# Delete deprecated files
rm src/data/models/alert.py
rm src/data/models/finding.py
```

## Questions?

See `MIGRATION_ALERTS_TO_ANALYSIS.md` for complete migration documentation.
