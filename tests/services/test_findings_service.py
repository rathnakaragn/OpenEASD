"""
Comprehensive unit tests for FindingsService.

Tests business logic for finding management including listing,
retrieval, status updates, and statistics with proper mocking
of database dependencies.
"""

import pytest
from unittest.mock import MagicMock

from src.services.findings_service import (
    FindingsService,
    FindingNotFound,
    InvalidFindingStatus,
    VALID_STATUSES,
    VALID_SEVERITIES
)


@pytest.fixture
def mock_db_manager():
    """Mock database manager for testing."""
    db = MagicMock()
    return db


@pytest.fixture
def findings_service(mock_db_manager):
    """FindingsService instance with mocked database."""
    return FindingsService(db_manager=mock_db_manager)


@pytest.fixture
def sample_finding():
    """Sample finding for testing."""
    return {
        'finding_id': 'finding-123',
        'scan_id': 'scan-123',
        'affected_asset': 'api.example.com',
        'finding_type': 'exposed_mysql_service',
        'severity': 'critical',
        'status': 'new',
        'risk_score': 85,
        'title': 'Exposed MySQL Service',
        'description': 'MySQL 5.7 exposed on port 3306',
        'remediation': 'Update MySQL and restrict access',
        'discovered_at': '2025-01-01T10:00:00'
    }


# ========================================================================
# FindingsService Initialization Tests
# ========================================================================

def test_findings_service_initialization(mock_db_manager):
    """Test FindingsService initialization."""
    service = FindingsService(db_manager=mock_db_manager)
    assert service.db == mock_db_manager


# ========================================================================
# list_findings() Tests
# ========================================================================

def test_list_findings_no_filters(findings_service, mock_db_manager, sample_finding):
    """Test listing findings without filters."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1, 'limit': 100, 'offset': 0}
    }

    result = findings_service.list_findings()

    assert len(result['findings']) == 1
    assert result['findings'][0]['finding_id'] == 'finding-123'
    mock_db_manager.get_findings.assert_called_once_with(
        scan_id=None,
        affected_asset=None,
        min_severity=None,
        status=None,
        limit=100,
        offset=0
    )


def test_list_findings_with_scan_id(findings_service, mock_db_manager, sample_finding):
    """Test listing findings filtered by scan_id."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(scan_id='scan-123')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['scan_id'] == 'scan-123'


def test_list_findings_with_affected_asset(findings_service, mock_db_manager, sample_finding):
    """Test listing findings filtered by affected_asset."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(affected_asset='api.example.com')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['affected_asset'] == 'api.example.com'


def test_list_findings_with_min_severity(findings_service, mock_db_manager, sample_finding):
    """Test listing findings filtered by min_severity."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(min_severity='high')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['min_severity'] == 'high'


def test_list_findings_with_status(findings_service, mock_db_manager, sample_finding):
    """Test listing findings filtered by status."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(status='new')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['status'] == 'new'


def test_list_findings_with_pagination(findings_service, mock_db_manager, sample_finding):
    """Test listing findings with pagination."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding] * 50,
        'pagination': {'total': 100, 'limit': 50, 'offset': 0}
    }

    result = findings_service.list_findings(limit=50, offset=0)

    assert len(result['findings']) == 50
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['limit'] == 50
    assert call_args['offset'] == 0


def test_list_findings_empty(findings_service, mock_db_manager):
    """Test listing findings when none exist."""
    mock_db_manager.get_findings.return_value = {
        'findings': [],
        'pagination': {'total': 0}
    }

    result = findings_service.list_findings()

    assert len(result.get('findings', [])) == 0


def test_list_findings_invalid_severity(findings_service, mock_db_manager, sample_finding):
    """Test listing with invalid severity filter (should be ignored)."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(min_severity='invalid')

    # Invalid severity should be ignored, passed as None
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['min_severity'] is None


def test_list_findings_invalid_status(findings_service, mock_db_manager, sample_finding):
    """Test listing with invalid status filter (should be ignored)."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(status='invalid')

    # Invalid status should be ignored, passed as None
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['status'] is None


def test_list_findings_all_valid_severities(findings_service, mock_db_manager):
    """Test all valid severity levels."""
    mock_db_manager.get_findings.return_value = {'findings': [], 'pagination': {}}

    for severity in VALID_SEVERITIES:
        findings_service.list_findings(min_severity=severity)
        call_args = mock_db_manager.get_findings.call_args[1]
        assert call_args['min_severity'] == severity


def test_list_findings_all_valid_statuses(findings_service, mock_db_manager):
    """Test all valid status levels."""
    mock_db_manager.get_findings.return_value = {'findings': [], 'pagination': {}}

    for status in VALID_STATUSES:
        findings_service.list_findings(status=status)
        call_args = mock_db_manager.get_findings.call_args[1]
        assert call_args['status'] == status


# ========================================================================
# get_finding() Tests
# ========================================================================

def test_get_finding_success(findings_service, mock_db_manager, sample_finding):
    """Test successful finding retrieval."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding

    result = findings_service.get_finding('finding-123')

    assert result['finding_id'] == 'finding-123'
    assert result['severity'] == 'critical'
    mock_db_manager.get_finding_by_id.assert_called_once_with('finding-123')


def test_get_finding_not_found(findings_service, mock_db_manager):
    """Test retrieving a non-existent finding."""
    mock_db_manager.get_finding_by_id.return_value = None

    with pytest.raises(FindingNotFound) as exc_info:
        findings_service.get_finding('nonexistent')

    assert 'nonexistent' in str(exc_info.value)


def test_get_finding_returns_complete_data(findings_service, mock_db_manager, sample_finding):
    """Test that get_finding returns complete finding data."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding

    result = findings_service.get_finding('finding-123')

    assert 'finding_id' in result
    assert 'scan_id' in result
    assert 'affected_asset' in result
    assert 'severity' in result
    assert 'status' in result


# ========================================================================
# update_status() Tests
# ========================================================================

def test_update_status_success(findings_service, mock_db_manager, sample_finding):
    """Test successful status update."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = True

    result = findings_service.update_status(
        finding_id='finding-123',
        status='resolved',
        resolution_notes='Fixed by patching MySQL'
    )

    assert result['success'] is True
    assert result['finding_id'] == 'finding-123'
    assert result['new_status'] == 'resolved'
    mock_db_manager.update_finding_status.assert_called_once_with(
        finding_id='finding-123',
        status='resolved',
        resolution_notes='Fixed by patching MySQL'
    )


def test_update_status_finding_not_found(findings_service, mock_db_manager):
    """Test updating status of non-existent finding."""
    mock_db_manager.get_finding_by_id.return_value = None

    with pytest.raises(FindingNotFound) as exc_info:
        findings_service.update_status('nonexistent', 'resolved')

    assert 'nonexistent' in str(exc_info.value)
    mock_db_manager.update_finding_status.assert_not_called()


def test_update_status_invalid_status(findings_service, mock_db_manager, sample_finding):
    """Test updating with invalid status."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding

    with pytest.raises(InvalidFindingStatus) as exc_info:
        findings_service.update_status('finding-123', 'invalid_status')

    assert 'Invalid status' in str(exc_info.value)
    mock_db_manager.update_finding_status.assert_not_called()


def test_update_status_all_valid_statuses(findings_service, mock_db_manager, sample_finding):
    """Test updating to all valid statuses."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = True

    for status in VALID_STATUSES:
        result = findings_service.update_status('finding-123', status)
        assert result['success'] is True
        assert result['new_status'] == status


def test_update_status_without_notes(findings_service, mock_db_manager, sample_finding):
    """Test status update without resolution notes."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = True

    result = findings_service.update_status('finding-123', 'acknowledged')

    assert result['success'] is True
    mock_db_manager.update_finding_status.assert_called_once_with(
        finding_id='finding-123',
        status='acknowledged',
        resolution_notes=None
    )


def test_update_status_database_failure(findings_service, mock_db_manager, sample_finding):
    """Test status update when database operation fails."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = False

    result = findings_service.update_status('finding-123', 'resolved')

    assert result['success'] is False
    assert 'Failed to update' in result['message']


def test_update_status_reopened(findings_service, mock_db_manager, sample_finding):
    """Test reopening a resolved finding."""
    sample_finding['status'] = 'resolved'
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = True

    result = findings_service.update_status('finding-123', 'reopened')

    assert result['success'] is True
    assert result['new_status'] == 'reopened'


def test_update_status_false_positive(findings_service, mock_db_manager, sample_finding):
    """Test marking finding as false positive."""
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    mock_db_manager.update_finding_status.return_value = True

    result = findings_service.update_status(
        'finding-123',
        'false_positive',
        resolution_notes='Not a real vulnerability'
    )

    assert result['success'] is True
    assert result['new_status'] == 'false_positive'


# ========================================================================
# get_statistics() Tests
# ========================================================================

def test_get_statistics_no_filters(findings_service, mock_db_manager):
    """Test getting statistics without filters."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total': 100,
        'by_severity': {'critical': 10, 'high': 20, 'medium': 40, 'low': 30},
        'by_status': {'new': 50, 'open': 30, 'resolved': 20},
        'average_risk_score': 65.5
    }

    result = findings_service.get_statistics()

    assert result['total'] == 100
    assert result['by_severity']['critical'] == 10
    mock_db_manager.get_findings_statistics.assert_called_once_with(
        scan_id=None,
        affected_asset=None
    )


def test_get_statistics_with_scan_id(findings_service, mock_db_manager):
    """Test getting statistics filtered by scan_id."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total': 25,
        'by_severity': {'critical': 5, 'high': 10, 'medium': 10},
        'by_status': {'new': 25}
    }

    result = findings_service.get_statistics(scan_id='scan-123')

    assert result['total'] == 25
    mock_db_manager.get_findings_statistics.assert_called_once()
    call_args = mock_db_manager.get_findings_statistics.call_args[1]
    assert call_args['scan_id'] == 'scan-123'


def test_get_statistics_with_affected_asset(findings_service, mock_db_manager):
    """Test getting statistics filtered by affected_asset."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total': 15,
        'by_severity': {'critical': 3, 'high': 7, 'medium': 5},
        'by_status': {'new': 10, 'resolved': 5}
    }

    result = findings_service.get_statistics(affected_asset='api.example.com')

    assert result['total'] == 15
    mock_db_manager.get_findings_statistics.assert_called_once()
    call_args = mock_db_manager.get_findings_statistics.call_args[1]
    assert call_args['affected_asset'] == 'api.example.com'


def test_get_statistics_empty(findings_service, mock_db_manager):
    """Test getting statistics when no findings exist."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total': 0,
        'by_severity': {},
        'by_status': {}
    }

    result = findings_service.get_statistics()

    assert result['total'] == 0


def test_get_statistics_with_both_filters(findings_service, mock_db_manager):
    """Test getting statistics with both scan_id and asset filters."""
    mock_db_manager.get_findings_statistics.return_value = {
        'total': 5,
        'by_severity': {'critical': 2, 'high': 3}
    }

    result = findings_service.get_statistics(
        scan_id='scan-123',
        affected_asset='api.example.com'
    )

    assert result['total'] == 5
    call_args = mock_db_manager.get_findings_statistics.call_args[1]
    assert call_args['scan_id'] == 'scan-123'
    assert call_args['affected_asset'] == 'api.example.com'


# ========================================================================
# get_findings_by_scan() Tests
# ========================================================================

def test_get_findings_by_scan_success(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by scan ID."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.get_findings_by_scan('scan-123')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['scan_id'] == 'scan-123'


def test_get_findings_by_scan_with_severity(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by scan with severity filter."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.get_findings_by_scan('scan-123', min_severity='high')

    assert len(result['findings']) == 1
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['scan_id'] == 'scan-123'
    assert call_args['min_severity'] == 'high'


def test_get_findings_by_scan_with_pagination(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by scan with pagination."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding] * 20,
        'pagination': {'total': 50, 'limit': 20, 'offset': 0}
    }

    result = findings_service.get_findings_by_scan('scan-123', limit=20, offset=0)

    assert len(result['findings']) == 20
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['limit'] == 20
    assert call_args['offset'] == 0


def test_get_findings_by_scan_empty(findings_service, mock_db_manager):
    """Test getting findings by scan when none exist."""
    mock_db_manager.get_findings.return_value = {
        'findings': [],
        'pagination': {'total': 0}
    }

    result = findings_service.get_findings_by_scan('scan-123')

    assert len(result.get('findings', [])) == 0


# ========================================================================
# get_findings_by_asset() Tests
# ========================================================================

def test_get_findings_by_asset_success(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by asset name."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.get_findings_by_asset('api.example.com')

    assert len(result['findings']) == 1
    mock_db_manager.get_findings.assert_called_once()
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['affected_asset'] == 'api.example.com'


def test_get_findings_by_asset_with_severity(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by asset with severity filter."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.get_findings_by_asset('api.example.com', min_severity='critical')

    assert len(result['findings']) == 1
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['affected_asset'] == 'api.example.com'
    assert call_args['min_severity'] == 'critical'


def test_get_findings_by_asset_with_pagination(findings_service, mock_db_manager, sample_finding):
    """Test getting findings by asset with pagination."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding] * 50,
        'pagination': {'total': 100, 'limit': 50, 'offset': 50}
    }

    result = findings_service.get_findings_by_asset('api.example.com', limit=50, offset=50)

    assert len(result['findings']) == 50
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['limit'] == 50
    assert call_args['offset'] == 50


def test_get_findings_by_asset_empty(findings_service, mock_db_manager):
    """Test getting findings by asset when none exist."""
    mock_db_manager.get_findings.return_value = {
        'findings': [],
        'pagination': {'total': 0}
    }

    result = findings_service.get_findings_by_asset('api.example.com')

    assert len(result.get('findings', [])) == 0


def test_get_findings_by_asset_multiple_assets(findings_service, mock_db_manager):
    """Test getting findings for different assets."""
    mock_db_manager.get_findings.return_value = {'findings': [], 'pagination': {}}

    assets = ['api.example.com', 'www.example.com', '1.2.3.4']
    for asset in assets:
        findings_service.get_findings_by_asset(asset)
        call_args = mock_db_manager.get_findings.call_args[1]
        assert call_args['affected_asset'] == asset


# ========================================================================
# Edge Cases and Integration
# ========================================================================

def test_constants_are_valid():
    """Test that constants are properly defined."""
    assert len(VALID_STATUSES) > 0
    assert len(VALID_SEVERITIES) > 0
    assert 'critical' in VALID_SEVERITIES
    assert 'resolved' in VALID_STATUSES


def test_multiple_operations_same_finding(findings_service, mock_db_manager, sample_finding):
    """Test multiple operations on same finding."""
    # Get finding
    mock_db_manager.get_finding_by_id.return_value = sample_finding
    result = findings_service.get_finding('finding-123')
    assert result['finding_id'] == 'finding-123'

    # Update status
    mock_db_manager.update_finding_status.return_value = True
    result = findings_service.update_status('finding-123', 'acknowledged')
    assert result['success'] is True

    # Get again
    result = findings_service.get_finding('finding-123')
    assert result['finding_id'] == 'finding-123'


def test_list_findings_with_all_parameters(findings_service, mock_db_manager, sample_finding):
    """Test listing with all filter parameters."""
    mock_db_manager.get_findings.return_value = {
        'findings': [sample_finding],
        'pagination': {'total': 1}
    }

    result = findings_service.list_findings(
        scan_id='scan-123',
        affected_asset='api.example.com',
        min_severity='high',
        status='new',
        limit=50,
        offset=10
    )

    assert len(result['findings']) == 1
    call_args = mock_db_manager.get_findings.call_args[1]
    assert call_args['scan_id'] == 'scan-123'
    assert call_args['affected_asset'] == 'api.example.com'
    assert call_args['min_severity'] == 'high'
    assert call_args['status'] == 'new'
    assert call_args['limit'] == 50
    assert call_args['offset'] == 10
