
import pytest
from pathlib import Path
from src.analysis.config import AnalysisConfig, get_analysis_config

@pytest.fixture
def dummy_config_path():
    """Returns the path to the dummy config file."""
    return Path(__file__).parent / "dummy_config.yaml"

def test_config_loading(dummy_config_path):
    """Test that the config is loaded correctly from a yaml file."""
    config = AnalysisConfig(config_path=str(dummy_config_path))
    assert config.get('analysis.enabled') is True
    assert config.get('analysis.scoring.algorithm') == 'custom'
    assert config.get('analysis.detectors.port_detector.high_risk_ports') == [21, 22]

def test_default_config_loading():
    """Test that default config is loaded when the file doesn't exist."""
    config = AnalysisConfig(config_path="non_existent_file.yaml")
    assert config.get('analysis.enabled') is True
    assert config.get('analysis.scoring.algorithm') == 'deterministic'

def test_get_method(dummy_config_path):
    """Test the get method for retrieving config values."""
    config = AnalysisConfig(config_path=str(dummy_config_path))
    assert config.get('analysis.scoring.critical_threshold') == 85
    assert config.get('non_existent_key', 'default_value') == 'default_value'
    assert config.get('analysis.non_existent.key', 'default') == 'default'

def test_helper_methods(dummy_config_path):
    """Test the various helper methods."""
    config = AnalysisConfig(config_path=str(dummy_config_path))
    assert config.is_enabled()
    assert config.is_auto_analyze_enabled()
    assert config.get_high_risk_ports() == [21, 22]
    assert config.get_medium_risk_ports() == [] # Not in dummy config
    
    thresholds = config.get_severity_thresholds()
    assert thresholds['critical'] == 85
    assert thresholds['high'] == 60 # default

def test_get_analysis_config_singleton():
    """Test that get_analysis_config returns a singleton instance."""
    config1 = get_analysis_config()
    config2 = get_analysis_config()
    assert config1 is config2
