
import pytest
from unittest.mock import patch, MagicMock
from src.analysis.scoring.risk_scorer import RiskScorer

@pytest.fixture
def mock_config():
    """Fixture for a mocked analysis configuration."""
    config = MagicMock()
    config.get.side_effect = lambda key, default: {
        'analysis.scoring.base_score_weight': 0.4,
        'analysis.scoring.context_score_weight': 0.4,
        'analysis.scoring.exposure_score_weight': 0.2,
        'analysis.detectors.port_detector.database_ports': [3306, 5432],
        'analysis.detectors.port_detector.auth_ports': [389, 636],
    }.get(key, default)
    config.get_severity_thresholds.return_value = {
        'critical': 80,
        'high': 60,
        'medium': 40,
        'low': 20,
    }
    return config

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_risk_scorer_init(mock_get_config, mock_config):
    """Test RiskScorer initialization."""
    mock_get_config.return_value = mock_config
    scorer = RiskScorer()
    assert scorer.base_weight == 0.4
    assert scorer.thresholds['critical'] == 80

def create_scorer(mock_get_config, mock_config):
    mock_get_config.return_value = mock_config
    return RiskScorer()

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_calculate_risk_score(mock_get_config, mock_config):
    """Test the overall risk score calculation."""
    scorer = create_scorer(mock_get_config, mock_config)
    finding = {
        'finding_type': 'database_port_exposed',
        'affected_asset': 'prod-db.example.com',
        'port': 3306,
        'status': 'active'
    }
    # Base=40, Context=35 (20+15), Exposure=20 (15+5)
    # Expected: 40 * 1 + 35 * 1 + 20 * 1 = 95
    assert scorer.calculate_risk_score(finding) == 95

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_base_score_calculation(mock_get_config, mock_config):
    """Test the base score calculation logic."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer._calculate_base_score({'finding_type': 'remote_code_execution'}) == 40
    assert scorer._calculate_base_score({'finding_type': 'subdomain_discovered'}) == 10
    assert scorer._calculate_base_score({'finding_type': 'new_vulnerable_lib'}) == 30 # dynamic based on 'vulnerable'

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_context_score_calculation(mock_get_config, mock_config):
    """Test the context score calculation."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer._calculate_context_score({'affected_asset': 'api.example.com'}) == 20
    assert scorer._calculate_context_score({'affected_asset': 'test-server'}) == 5
    assert scorer._calculate_context_score({'port': 5432}) == 15
    assert scorer._calculate_context_score({'affected_asset': 'admin.portal', 'port': 389}) == 40 # 10+15 -> capped at 40

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_exposure_score_calculation(mock_get_config, mock_config):
    """Test the exposure score calculation."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer._calculate_exposure_score({'affected_asset': 'public.net', 'status': 'responsive'}) == 20
    assert scorer._calculate_exposure_score({'affected_asset': '10.0.0.1'}) == 0
    assert scorer._calculate_exposure_score({'affected_asset': 'localhost', 'port': 8080}) == 5
    
@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_is_publicly_accessible(mock_get_config, mock_config):
    """Test the public accessibility check."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer._is_publicly_accessible('example.com')
    assert not scorer._is_publicly_accessible('192.168.1.1')
    assert not scorer._is_publicly_accessible('server.local')

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_map_score_to_severity(mock_get_config, mock_config):
    """Test mapping of score to severity."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer.map_score_to_severity(90) == 'critical'
    assert scorer.map_score_to_severity(70) == 'high'
    assert scorer.map_score_to_severity(50) == 'medium'
    assert scorer.map_score_to_severity(30) == 'low'
    assert scorer.map_score_to_severity(10) == 'info'

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_score_finding(mock_get_config, mock_config):
    """Test the complete finding scoring process."""
    scorer = create_scorer(mock_get_config, mock_config)
    finding = {'finding_type': 'open_http_port', 'affected_asset': 'app.example.com'}
    scored_finding = scorer.score_finding(finding)
    assert 'risk_score' in scored_finding
    assert 'severity' in scored_finding
    assert 'score_breakdown' in scored_finding
    assert scored_finding['severity'] == 'medium' # Base=15, Context=20, Exposure=15 -> Score ~43

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_score_finding_with_critical_hint(mock_get_config, mock_config):
    """Test that a critical hint overrides a lower calculated score."""
    scorer = create_scorer(mock_get_config, mock_config)
    finding = {'finding_type': 'low_risk_thing', 'affected_asset': 'internal.dev', 'severity_hint': 'critical'}
    scored_finding = scorer.score_finding(finding)
    assert scored_finding['risk_score'] == 80
    assert scored_finding['severity'] == 'critical'

@patch('src.analysis.scoring.risk_scorer.get_analysis_config')
def test_get_confidence_level(mock_get_config, mock_config):
    """Test confidence level determination."""
    scorer = create_scorer(mock_get_config, mock_config)
    assert scorer.get_confidence_level({'verified': True, 'evidence': {'key': 'val'}}) == 'high'
    assert scorer.get_confidence_level({'evidence': {'key': 'val'}}) == 'medium'
    assert scorer.get_confidence_level({'finding_type': 'database_port_exposed'}) == 'medium'
    assert scorer.get_confidence_level({}) == 'low'
