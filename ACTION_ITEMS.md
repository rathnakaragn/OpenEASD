# Action Items - OpenEASD Code Review

**Generated**: November 25, 2025
**Priority Order**: By Impact & Effort

---

## 🔴 CRITICAL (Do First)

### 1. Fix Missing Database Method
**Time**: 30 minutes
**Impact**: HIGH - Breaks delete functionality

**File**: `src/data/database/sqlmodel_manager.py`

**Issue**: Method `get_domain_data_totals()` is called but not implemented

**Action**:
```python
def get_domain_data_totals(self, domain: str) -> Dict[str, Any]:
    """Get counts of data associated with a domain."""
    with Session(self.engine) as session:
        # Count associated data
        # Return dict with counts
        pass
```

**Files affected**:
- `src/services/domain_service.py:220`

---

### 2. Replace Raw SQL Queries
**Time**: 1-2 hours
**Impact**: HIGH - Type safety & security

**Files**:
- `src/services/scan_service.py:210-215` (get_scan_results)
- `src/services/scan_service.py:272-285` (list_scans)

**Action**: Create proper database manager methods:
```python
# Add to SQLModelManager:
def list_scans(self, limit: int = 20) -> Dict[str, Any]:
    """List scan sessions."""
    
def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
    """Get scan results including alerts."""
```

Then use these methods in services instead of raw SQL.

---

### 3. Fix Database Connection Access
**Time**: 1 hour
**Impact**: MEDIUM - Code quality

**Action**: Replace all `self.db.connection.execute()` calls with proper manager methods.

**Current Pattern (BAD)**:
```python
self.db.connection.execute("SELECT * FROM ...")
```

**New Pattern (GOOD)**:
```python
self.db.get_scan_results(scan_id)  # Use manager method
```

**Locations**:
- `src/services/scan_service.py:210-215`
- `src/services/scan_service.py:272-285`

---

## 🟡 HIGH PRIORITY (Do Next)

### 4. Add Logging
**Time**: 2 hours
**Impact**: MEDIUM - Debuggability

**Action**: Add structured logging to all service methods.

```python
import logging
logger = logging.getLogger(__name__)

def create_domain(self, domain: str, **kwargs):
    logger.info(f"Creating domain: {domain}")
    try:
        # ... code
        logger.info(f"Domain created: {domain}")
    except Exception as e:
        logger.error(f"Failed to create domain {domain}: {e}")
        raise
```

**Files**:
- `src/services/domain_service.py`
- `src/services/scan_service.py`
- `src/services/alert_service.py`

---

### 5. Configurable Tool Timeouts
**Time**: 1 hour
**Impact**: LOW - Nice to have

**Action**: Move hard-coded timeouts to config.

**Current (BAD)**:
```python
result = run_subfinder(domain, timeout=30)
```

**New (GOOD)**:
```python
timeout = self.config.get('tool_timeouts', {}).get('subfinder', 30)
result = run_subfinder(domain, timeout=timeout)
```

**Locations**:
- `src/cli/commands.py` - All tool execution calls
- Add to `config/recon_config.yaml`

---

## 🟢 MEDIUM PRIORITY (When Convenient)

### 6. Improve Tool Output Parsing
**Time**: 2 hours
**Impact**: LOW - Robustness

**Current Issue** (Lines 223-234 in scan_service.py):
```python
# Fragile parsing of port from description
port_num = int(parts[0])  # Could fail silently
```

**Fix**: Use structured data instead of parsing description strings.

---

### 7. Complete Type Hints
**Time**: 1 hour
**Impact**: LOW - IDE support

Add return type annotations where missing:
```python
def execute_scan(self, domain: str) -> Dict[str, Any]:
    """Better: specify exact keys"""
```

---

### 8. Add Docstring Examples
**Time**: 1 hour
**Impact**: LOW - Documentation

Add usage examples to service methods:
```python
def create_domain(self, domain: str) -> Dict[str, Any]:
    """
    Create a new domain.
    
    Example:
        >>> service.create_domain('example.com', is_primary=True)
        {'success': True, 'domain': {...}}
    """
```

---

## 📋 Testing & Validation

### 9. Run Test Suite
**Time**: 5 minutes
**Command**: 
```bash
pytest tests/ -v --tb=short
```

**Expected**: ~110+ tests passing, some database tests may need updates

---

### 10. Fix Test Assertion Mismatches
**Time**: 1-2 hours
**Impact**: MEDIUM - Test reliability

Update test assertions to match actual API responses:

**Files**:
- `tests/test_database_manager.py` - Update response format assertions
- `tests/test_api_endpoints.py` - Verify with real API

---

## 🚀 Deployment Checklist

- [ ] Fix Critical Issues (1-3)
- [ ] Fix High Priority Issues (4-5)
- [ ] Run full test suite
- [ ] Generate coverage report
- [ ] Update documentation
- [ ] Deploy to staging
- [ ] Run integration tests
- [ ] Deploy to production

---

## 📊 Effort Estimate

| Priority | Items | Time | Total |
|----------|-------|------|-------|
| Critical | 3 | 30min-2hr | 4-5 hours |
| High | 2 | 1-2 hours | 3-4 hours |
| Medium | 3 | 1-2 hours | 3-4 hours |
| **Total** | **8** | **3-6 hours** | **10-13 hours** |

---

## 📞 Questions & Notes

### Q: Can we deploy before fixing these issues?
**A**: The critical issues affect specific functionality:
- Issue #1 breaks `delete_domain(force=False)`
- Issues #2-3 are code quality, not functional bugs

You can deploy if you don't use those specific features.

### Q: Will tests break the build?
**A**: Some database tests may need adjustment for response formats. Start with:
```bash
pytest tests/test_validation.py tests/test_domain_service.py -v
```

These should all pass without changes.

### Q: What's the biggest risk?
**A**: Using `delete_domain(force=False)` will crash due to missing method. Use `force=True` for now.

---

**Last Updated**: November 25, 2025
**Status**: ✅ Ready to Action
