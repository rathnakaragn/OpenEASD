# Alerts and Findings Migration to Analysis Layer

**Status**: Phase 1 & 2 Complete ✅ (Cleanup Remaining)
**Date**: November 26, 2025
**Author**: Claude Code

## Overview

This document tracks the migration of all alerts and findings code from disparate locations into the **Analysis Layer** for unified management.

### Why This Migration?

**Before**: Alerts and findings were scattered across:
- `SecurityAlert` model in data layer
- `Finding` model in data layer
- `AlertService` in service layer
- Alert endpoints in API layer
- Direct alert creation in CLI commands

**After**: All alerts/findings consolidated in:
- **Analysis Layer** models (`src/analysis/models.py`)
- **Analysis Layer** service (`src/analysis/alert_service.py`)
- **Unified database storage** (findings table only)
- **Single API** for alert/finding retrieval

## Migration Progress

### ✅ Phase 1: Complete (Core Infrastructure)

#### 1.1 Created Analysis Layer Alert Service
**File**: `src/analysis/alert_service.py`

New `AlertManagementService` provides:
- Unified alert creation from scan results
- Alert-to-finding conversion
- Alert retrieval with filtering
- Status management
- Statistics generation
- Backward compatibility with alert format

```python
# Example: Create alerts from scan
alert_service = AlertManagementService(db_manager)

finding = alert_service.create_alert_from_scan(
    scan_id="scan-uuid",
    domain="example.com",
    vulnerability_type="open_port",
    severity="low",
    description="Open port 443 detected",
    tool_source="naabu"
)

# Store as findings
alert_service.store_alerts([finding])

# Retrieve with filtering
alerts = alert_service.get_alerts(
    min_severity="medium",
    limit=100
)
```

#### 1.2 Created Analysis Layer Models
**File**: `src/analysis/models.py`

Moved models from `src/data/models/finding.py`:
- `Finding` - Core finding model with risk scoring
- `Vulnerability` - CVE-enriched vulnerability records
- `CVEMapping` - Links findings to CVEs
- `FindingGroup` - Groups related findings

#### 1.3 Updated Database Layer
**File**: `src/data/database/sqlmodel_manager.py`

Changes:
- ✅ Imports `Finding`, `Vulnerability`, `CVEMapping`, `FindingGroup` from `src/analysis.models`
- ✅ Removed `SecurityAlert` import (no longer used)
- ✅ `store_alerts()` now delegates to `store_findings()`
- ✅ `get_alert_by_id()` now delegates to `get_finding_by_id()`
- ✅ `get_alerts()` now delegates to `get_findings()`

#### 1.4 Updated Analysis Layer Exports
**File**: `src/analysis/__init__.py`

Now exports:
- `AnalysisService`
- `AlertManagementService` (NEW)
- `Finding`, `Vulnerability`, `CVEMapping`, `FindingGroup`

### ✅ Phase 2: Complete (Integration)

#### 2.1 Update Service Layer
**File**: `src/services/alert_service.py`

Completed:
- [x] Updated `AlertService` to use `AlertManagementService` from analysis layer
- [x] Removed old alert formatting logic (now handled by AlertManagementService)
- [x] Maintained backward compatibility through wrapper methods
- [x] Added support for `min_severity` filter

**Changes Made**:
```python
class AlertService:
    def __init__(self, db_manager):
        self.db = db_manager
        # Initialize analysis layer alert service
        self.alert_mgmt_service = AlertManagementService(db_manager)

    def list_alerts(self, limit, severity, domain, min_severity):
        # Delegates to analysis layer
        result = self.alert_mgmt_service.get_alerts(...)
        return {'success': True, 'alerts': result.get('alerts')}
```

#### 2.2 Update API Routes
**File**: `src/api/routes/alerts.py`

Completed:
- [x] API routes automatically use updated `AlertService`
- [x] Added `min_severity` query parameter to `/api/v1/alerts`
- [x] Maintained same endpoint interface for backward compatibility
- [x] Updated documentation to mention Analysis Layer

**New API Parameter**:
```bash
GET /api/v1/alerts?min_severity=medium  # Excludes low/info
```

#### 2.3 Update CLI Commands
**File**: `src/cli/commands_scan.py`

Completed:
- [x] Updated to use `AlertManagementService` from analysis layer
- [x] Convert alerts to findings using `create_alert_batch()`
- [x] Store through analysis layer with `store_alerts()`
- [x] Added port and protocol fields for better context

**Changes Made**:
```python
from src.analysis.alert_service import AlertManagementService

alert_service = AlertManagementService(db_manager)
findings = alert_service.create_alert_batch(scan_id, alerts)
alert_service.store_alerts(findings)  # Stored as findings with risk scoring
```

### ✅ Phase 3: Cleanup (Complete)

#### 3.1 Remove Old SecurityAlert References
**File**: `src/data/database/sqlmodel_manager.py`

Completed:
- [x] Replaced all `SecurityAlert` references with `Finding`
- [x] Updated domain deletion preview to count findings
- [x] Updated domain deletion to delete findings
- [x] Updated database metrics to use findings
- [x] Removed `_alert_to_dict()` helper method
- [x] Added backward compatibility fields

#### 3.2 Update Data Models Init
**File**: `src/data/models/__init__.py`

Completed:
- [x] Removed `SecurityAlert` import
- [x] Removed local `Finding` imports
- [x] Added imports from `src.analysis.models` for backward compatibility
- [x] Added deprecation notice in docstring

**New Structure**:
```python
# Import from analysis layer
from src.analysis.models import Finding, Vulnerability, CVEMapping, FindingGroup

# Backward compatible - old imports still work
from src.data.models import Finding  # Re-exported
```

#### 3.3 Model Files Status
**Files**: `src/data/models/alert.py`, `src/data/models/finding.py`

Status:
- Files are deprecated but kept for reference
- See `DEPRECATED_MODELS_README.md` for migration guide
- Can be deleted once fully confident in migration
- All code now uses `src.analysis.models` directly or via re-export

#### 3.4 Database Tables
**security_alerts table**: DEPRECATED (optional cleanup)
- No longer used by active code
- All new data goes to `findings` table
- Can drop table: `DROP TABLE IF EXISTS security_alerts;`
- Or keep for historical data

## Data Structure Changes

### Alert → Finding Mapping

When alerts are stored through the new system, they're converted to findings:

```python
# Old alert structure
{
    'domain': 'example.com',
    'scan_id': '...',
    'vulnerability_type': 'open_port',
    'severity': 'low',
    'description': '...',
    'tool_source': 'naabu'
}

# Converted to finding
{
    'id': 'uuid',
    'affected_asset': 'example.com',  # from domain
    'scan_id': '...',
    'finding_type': 'port_exposed',  # mapped from vulnerability_type
    'severity': 'low',
    'title': '...',  # from description
    'risk_score': 30,  # calculated
    'detector': 'naabu',  # from tool_source
    'status': 'open',
    'discovered_at': '...',
    'evidence': {...},  # structured evidence
    'score_breakdown': {...}  # risk scoring detail
}
```

### Severity Mapping

| Finding Type | Severity | Risk Score |
|---|---|---|
| Database port exposed | Critical | 90 |
| High-risk service | High | 70 |
| Subdomain discovered | Low | 30 |
| Open port (80, 443) | Low | 30 |
| TLS weakness | Medium | 50 |

## Key Benefits

✅ **Unified Management**: Single source of truth for all security findings
✅ **Risk Scoring**: All findings get deterministic 0-100 risk scores
✅ **Better Severity**: Calculated from context, not hardcoded
✅ **Advanced Features**: Evidence, confidence, remediation, status tracking
✅ **Deduplication**: Automatic deduplication across detectors
✅ **CVE Integration**: Findings can be mapped to CVEs
✅ **Consistency**: Same data model used throughout system

## Implementation Checklist

- [x] Create `AlertManagementService` in analysis layer
- [x] Create `models.py` in analysis layer
- [x] Update database layer imports
- [x] Redirect alert methods to findings
- [x] Update analysis layer exports
- [ ] Update service layer (`AlertService`)
- [ ] Update API routes (`alerts.py`)
- [ ] Update CLI commands (`commands_scan.py`)
- [ ] Remove `SecurityAlert` model
- [ ] Remove old `Finding` model from data layer
- [ ] Clean up imports throughout codebase
- [ ] Add database migration (optional)
- [ ] Update documentation
- [ ] Run full test suite

## Migration Guide for Developers

### Old Way (Deprecated)
```python
# Create alerts directly
alerts = [
    {
        'domain': 'example.com',
        'scan_id': scan_id,
        'vulnerability_type': 'open_port',
        'severity': 'low',
        'description': 'Open port 443',
        'tool_source': 'naabu',
        'discovered_at': get_ist_now()
    }
]
db_manager.store_alerts(alerts)
```

### New Way (Recommended)
```python
from src.analysis import AlertManagementService

alert_service = AlertManagementService(db_manager)

# Create alerts through analysis service
findings = alert_service.create_alert_batch(
    scan_id=scan_id,
    alerts=[
        {
            'domain': 'example.com',
            'vulnerability_type': 'open_port',
            'severity': 'low',
            'description': 'Open port 443',
            'tool_source': 'naabu'
        }
    ]
)

# Store findings (includes risk scoring)
alert_service.store_alerts(findings)

# Retrieve with advanced filtering
alerts = alert_service.get_alerts(
    min_severity='medium',  # Only medium+
    limit=100,
    offset=0
)
```

## Files Modified

### Created Files
- `src/analysis/alert_service.py` - New AlertManagementService
- `src/analysis/models.py` - Analysis layer models
- `MIGRATION_ALERTS_TO_ANALYSIS.md` - This file

### Modified Files
- `src/analysis/__init__.py` - Added exports for new service and models
- `src/data/database/sqlmodel_manager.py` - Updated imports, redirected methods

### Files to Remove (Phase 3)
- `src/data/models/alert.py` - Old SecurityAlert model
- `src/data/models/finding.py` - Old Finding model (after copying to analysis layer)

## Next Steps

1. **Phase 2 Implementation**
   - Update `AlertService` to use new `AlertManagementService`
   - Update API routes to import from analysis layer
   - Update CLI commands to use analysis service

2. **Testing**
   - Test alert creation through analysis service
   - Test alert retrieval and filtering
   - Test backward compatibility
   - Run existing alert tests

3. **Phase 3 Cleanup**
   - Delete old model files
   - Clean up imports
   - Verify no broken references
   - Optional: Database migration for SecurityAlert table

4. **Documentation**
   - Update DESIGN.md with new architecture
   - Update CLAUDE.md with best practices
   - Add examples to code comments

## Questions?

This migration consolidates alerts and findings into the Analysis Layer for better management and consistency. All existing functionality is preserved through delegation to the new unified system.
