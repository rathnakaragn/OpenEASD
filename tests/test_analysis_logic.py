"""
Unit tests for the analysis logic (Detectors, RiskScorer).
"""
import pytest
from unittest.mock import MagicMock

from src.analysis.detectors.port_detector import PortVulnerabilityDetector
from src.analysis.scoring.risk_scorer import RiskScorer
from src.analysis.config import AnalysisConfig


@pytest.fixture
def mock_analysis_config():
    """Mock AnalysisConfig for consistent testing."""
    mock_config = MagicMock(spec=AnalysisConfig)
    mock_config.get_high_risk_ports.return_value = [21, 23, 3389]
    mock_config.get_medium_risk_ports.return_value = [8080]
    # Ensure severity thresholds are returned
    mock_config.get_severity_thresholds.return_value = {
        'critical': 80, 'high': 60, 'medium': 40, 'low': 20
    }
    # Mock for httpx pdtm_path in runners.py
    mock_config.get.side_effect = lambda key, default: {
        'analysis.detectors.port_detector.enabled': True,
        'analysis.scoring.base_score_weight': 0.4,
        'analysis.scoring.context_score_weight': 0.4,
        'analysis.scoring.exposure_score_weight': 0.2,
        'analysis.scoring.critical_threshold': 80,
        'analysis.scoring.high_threshold': 60,
        'analysis.scoring.medium_threshold': 40,
        'analysis.scoring.low_threshold': 20,
        'tools.httpx.path': 'httpx', # Default httpx path
        'subfinder.timeout': 300,
        'naabu.top_ports': 1000,
        'naabu.timeout': 300,
        'workflow.default_timeout': 300,
        'tools.subfinder.path': 'subfinder',
        'tools.naabu.path': 'naabu',
        'tools.dnsx.path': 'dnsx',
        'port_info': {
            3306: {'name': 'MySQL', 'risk_level': 'critical', 'description': 'MySQL DB', 'remediation': 'Fix it'},
            5432: {'name': 'PostgreSQL', 'risk_level': 'critical', 'description': 'PostgreSQL DB', 'remediation': 'Fix it'}
        }
    }.get(key, default)
    return mock_config

@pytest.fixture
def port_detector(monkeypatch, mock_analysis_config):
    """Fixture for PortVulnerabilityDetector."""
    monkeypatch.setattr('src.analysis.detectors.port_detector.get_analysis_config', lambda: mock_analysis_config)
    return PortVulnerabilityDetector()

@pytest.fixture
def risk_scorer(monkeypatch, mock_analysis_config):
    """Fixture for RiskScorer."""
    monkeypatch.setattr('src.analysis.scoring.risk_scorer.get_analysis_config', lambda: mock_analysis_config)
    return RiskScorer()

# ============================================================================
# PortVulnerabilityDetector Tests
# ============================================================================

def test_port_detector_database_exposure(port_detector):
    """Test detector identifies database exposure."""
    scan_data = {
        'naabu_results': [{'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}]
    }
    findings = port_detector.analyze(scan_data)
    assert len(findings) == 1
    finding = findings[0]
    assert finding['finding_type'] == 'database_port_exposed'
    assert finding['severity_hint'] == 'critical'
    assert finding['port'] == 3306

def test_port_detector_multiple_findings(port_detector):
    """Test detector identifies multiple findings correctly."""
    scan_data = {
        'naabu_results': [
            {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},
            {'port': 23, 'target_host': 'telnet.example.com', 'protocol': 'tcp'}
        ]
    }
    findings = port_detector.analyze(scan_data)
    assert len(findings) == 3 # Expect 3 findings: high_risk, database for 3306, remote_access for 23
    db_high_risk = next((f for f in findings if f['finding_type'] == 'high_risk_port_exposed'), None)
    db_exposure = next((f for f in findings if f['finding_type'] == 'database_port_exposed'), None)
    critical_telnet = next((f for f in findings if f['finding_type'] == 'remote_access_exposed' and f['port'] == 23), None)
    assert db_high_risk is not None
    assert db_exposure is not None
    assert critical_telnet is not None
    assert db_exposure['severity_hint'] == 'critical'
    assert critical_telnet['severity_hint'] == 'critical'

def test_port_detector_empty_results(port_detector):
    """Test detector with empty naabu results."""
    scan_data = {'naabu_results': []}
    findings = port_detector.analyze(scan_data)
    assert len(findings) == 0

# ============================================================================
# RiskScorer Tests
# ============================================================================

def test_risk_scorer_critical_hint_override(risk_scorer):
    """Test risk scorer correctly overrides score for critical hints."""
    finding = {
        'finding_type': 'database_port_exposed',
        'affected_asset': 'db.example.com',
        'severity_hint': 'critical',
        'port': 3306
    }
    scored_finding = risk_scorer.score_finding(finding)
    assert scored_finding['risk_score'] >= 80
    assert scored_finding['severity'] == 'critical'

def test_risk_scorer_non_critical_hint(risk_scorer):
    """Test risk scorer for a non-critical hint (should calculate normally)."""
    finding = {
        'finding_type': 'subdomain_discovered',
        'affected_asset': 'sub.example.com',
        'severity_hint': 'info'
    }
    scored_finding = risk_scorer.score_finding(finding)
    assert scored_finding['risk_score'] == 25 # Base (10) + Exposure (15) = 25
    assert scored_finding['severity'] == 'low'
