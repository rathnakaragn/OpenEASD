
import pytest
from unittest.mock import MagicMock, patch

from src.analysis.analysis_service import AnalysisService

@pytest.fixture
def mock_db_manager():
    """Fixture for a mocked database manager."""
    db_manager = MagicMock()
    db_manager.store_findings = MagicMock()
    db_manager.get_findings = MagicMock(return_value={'findings': []})
    return db_manager

@pytest.fixture
def mock_config():
    """Fixture for a mocked analysis configuration."""
    config = MagicMock()
    config.get.side_effect = lambda key, default=None: {
        'analysis.detectors.port_detector.enabled': True,
        'analysis.detectors.port_detector': {}
    }.get(key, default)
    return config

@pytest.fixture
@patch('src.analysis.analysis_service.get_analysis_config')
@patch('src.analysis.analysis_service.RiskScorer')
@patch('src.analysis.analysis_service.PortVulnerabilityDetector')
def analysis_service(mock_port_detector, mock_risk_scorer, mock_get_config, mock_config, mock_db_manager):
    """Fixture to create an AnalysisService with mocked dependencies."""
    mock_get_config.return_value = mock_config
    
    # Mock instances of detectors and scorers
    mock_detector_instance = MagicMock()
    mock_detector_instance.analyze.return_value = [{'finding_type': 'test_finding'}]
    mock_detector_instance.is_enabled.return_value = True
    mock_detector_instance.get_name.return_value = 'MockDetector'
    mock_port_detector.return_value = mock_detector_instance

    mock_scorer_instance = MagicMock()
    mock_scorer_instance.score_finding.side_effect = lambda f: {**f, 'risk_score': 50, 'severity': 'medium'}
    mock_risk_scorer.return_value = mock_scorer_instance

    service = AnalysisService(db_manager=mock_db_manager)
    # Replace the loaded detectors with our mock instance
    service.detectors = [mock_detector_instance]
    service.risk_scorer = mock_scorer_instance
    return service

def test_analyze_scan_results_workflow(analysis_service, mock_db_manager):
    """Test the main analysis workflow."""
    scan_id = "test_scan_123"
    scan_data = {'naabu_results': [{'port': 80}]}

    result = analysis_service.analyze_scan_results(scan_id, scan_data)

    # Check that detectors were called
    assert analysis_service.detectors[0].analyze.called

    # Check that scorer was called
    assert analysis_service.risk_scorer.score_finding.called

    # Check that findings were stored
    analysis_service.db_manager.store_findings.assert_called()

    assert result['scan_id'] == scan_id
    assert result['findings_count'] == 1
    assert result['findings'][0]['severity'] == 'medium'

def test_deduplicate_findings(analysis_service):
    """Test the finding deduplication logic."""
    findings = [
        {'finding_type': 'open_port', 'affected_asset': 'a.com', 'port': 80, 'risk_score': 50},
        {'finding_type': 'open_port', 'affected_asset': 'a.com', 'port': 80, 'risk_score': 70}, # dupe, higher score
        {'finding_type': 'open_port', 'affected_asset': 'b.com', 'port': 443, 'risk_score': 30},
    ]
    deduped = analysis_service._deduplicate_findings(findings)
    assert len(deduped) == 2
    
    # Check that the one with the higher score was kept
    finding_a = next(f for f in deduped if f['affected_asset'] == 'a.com')
    assert finding_a['risk_score'] == 70

def test_generate_statistics(analysis_service):
    """Test the statistics generation."""
    findings = [{'severity': 'high', 'risk_score': 75}, {'severity': 'medium', 'risk_score': 50}]
    detector_stats = {'MockDetector': {'findings_count': 2, 'status': 'success'}}
    
    stats = analysis_service._generate_statistics(findings, detector_stats)
    
    assert stats['total_findings'] == 2
    assert stats['by_severity']['high'] == 1
    assert stats['highest_risk_score'] == 75
    assert stats['average_risk_score'] == 62.5

def test_get_scan_findings(analysis_service, mock_db_manager):
    """Test retrieving findings for a scan."""
    mock_db_manager.get_findings.return_value = {'findings': [{'id': '1'}]}
    findings = analysis_service.get_scan_findings("scan1")
    assert len(findings) == 1
    mock_db_manager.get_findings.assert_called_with(scan_id="scan1", min_severity=None)

def test_get_findings_by_asset(analysis_service, mock_db_manager):
    """Test retrieving findings for an asset."""
    mock_db_manager.get_findings.return_value = {'findings': [{'id': '2'}]}
    findings = analysis_service.get_findings_by_asset("asset.com")
    assert len(findings) == 1
    mock_db_manager.get_findings.assert_called_with(affected_asset="asset.com", limit=100)

def test_helper_methods(analysis_service):
    """Test simple helper/utility methods."""
    assert analysis_service.is_enabled()
    assert analysis_service.get_detector_count() == 1
    assert analysis_service.get_detector_names() == ['MockDetector']

def test_store_findings_no_db_manager():
    """Test that store_findings does not fail without a db_manager."""
    service = AnalysisService()  # No db_manager
    service.db_manager = None
    # This should run without raising an exception
    service._store_findings("scan-id", [])


@patch('src.analysis.analysis_service.get_analysis_config')
@patch('src.analysis.analysis_service.RiskScorer')
@patch('src.analysis.analysis_service.PortVulnerabilityDetector')
def test_analyze_scan_results_detector_error(mock_port_detector, mock_risk_scorer, mock_get_config, mock_config, mock_db_manager):
    """Test analysis workflow when a detector raises an exception."""
    mock_get_config.return_value = mock_config

    mock_detector_instance = MagicMock()
    mock_detector_instance.analyze.side_effect = Exception("Detector failed")
    mock_detector_instance.is_enabled.return_value = True
    mock_detector_instance.get_name.return_value = 'FaultyDetector'
    mock_port_detector.return_value = mock_detector_instance

    mock_scorer_instance = MagicMock()
    mock_risk_scorer.return_value = mock_scorer_instance

    service = AnalysisService(db_manager=mock_db_manager)
    service.detectors = [mock_detector_instance]

    result = service.analyze_scan_results("scan_id", {})

    assert result['findings_count'] == 0
    assert result['statistics']['by_detector']['FaultyDetector']['status'] == 'error'

@patch('src.analysis.analysis_service.get_analysis_config')
@patch('src.analysis.analysis_service.RiskScorer')
@patch('src.analysis.analysis_service.PortVulnerabilityDetector')
def test_analyze_scan_results_scorer_error(mock_port_detector, mock_risk_scorer, mock_get_config, mock_config, mock_db_manager):
    """Test analysis workflow when the risk scorer raises an exception."""
    mock_get_config.return_value = mock_config

    mock_detector_instance = MagicMock()
    mock_detector_instance.analyze.return_value = [{'finding_type': 'test_finding'}]
    mock_detector_instance.is_enabled.return_value = True
    mock_detector_instance.get_name.return_value = 'MockDetector'
    mock_port_detector.return_value = mock_detector_instance

    mock_scorer_instance = MagicMock()
    mock_scorer_instance.score_finding.side_effect = Exception("Scorer failed")
    mock_risk_scorer.return_value = mock_scorer_instance

    service = AnalysisService(db_manager=mock_db_manager)
    service.detectors = [mock_detector_instance]
    service.risk_scorer = mock_scorer_instance

    result = service.analyze_scan_results("scan_id", {})

    assert result['findings_count'] == 1
    # Check that the finding has default scores
    assert result['findings'][0]['risk_score'] == 50
    assert result['findings'][0]['severity'] == 'medium'

@patch('src.analysis.analysis_service.get_analysis_config')
@patch('src.analysis.analysis_service.RiskScorer')
@patch('src.analysis.analysis_service.PortVulnerabilityDetector')
def test_full_analysis_failure(mock_port_detector, mock_risk_scorer, mock_get_config, mock_config, mock_db_manager):
    """Test that a major failure in the analysis service is caught and raises an exception."""
    mock_get_config.return_value = mock_config

    mock_detector_instance = MagicMock()
    # Make a required part of the data missing to cause a failure down the line
    mock_detector_instance.analyze.return_value = [{}]  # Missing finding_type
    mock_detector_instance.is_enabled.return_value = True
    mock_detector_instance.get_name.return_value = 'BadDataDetector'
    mock_port_detector.return_value = mock_detector_instance

    # Let the scorer fail on bad data
    mock_scorer_instance = MagicMock()
    mock_scorer_instance.score_finding.side_effect = KeyError("finding_type")
    mock_risk_scorer.return_value = mock_scorer_instance

    service = AnalysisService(db_manager=mock_db_manager)
    service.detectors = [mock_detector_instance]
    service.risk_scorer = mock_scorer_instance

    result = service.analyze_scan_results("scan_id", {})
    assert result['findings_count'] == 1
    assert result['findings'][0]['risk_score'] == 50
    assert result['findings'][0]['severity'] == 'medium'
