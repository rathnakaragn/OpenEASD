
import pytest
from src.analysis.detectors.base_detector import BaseDetector

# A concrete implementation of BaseDetector for testing
class ConcreteDetector(BaseDetector):
    def analyze(self, scan_data):
        return [self._create_finding(
            finding_type='test_finding',
            title='Test Finding',
            description='This is a test finding.',
            affected_asset='test.com',
            severity_hint='low'
        )]

def test_base_detector_init():
    """Test initialization of the base detector."""
    detector = ConcreteDetector(config={'enabled': False})
    assert not detector.is_enabled()
    
    detector_default = ConcreteDetector()
    assert detector_default.is_enabled()

def test_get_name():
    """Test the get_name method."""
    detector = ConcreteDetector()
    assert detector.get_name() == 'ConcreteDetector'

def test_create_finding():
    """Test the finding creation helper method."""
    detector = ConcreteDetector()
    finding = detector._create_finding(
        finding_type='sample_type',
        title='Sample Title',
        description='Sample Description',
        affected_asset='sample.com',
        severity_hint='high',
        port=8080,
        evidence={'log': 'some data'}
    )
    
    assert finding['finding_type'] == 'sample_type'
    assert finding['title'] == 'Sample Title'
    assert finding['affected_asset'] == 'sample.com'
    assert finding['severity_hint'] == 'high'
    assert finding['port'] == 8080
    assert finding['detector'] == 'ConcreteDetector'
    assert 'evidence' in finding

def test_analyze_method():
    """Test that the analyze method of the concrete implementation works."""
    detector = ConcreteDetector()
    findings = detector.analyze({})
    assert len(findings) == 1
    assert findings[0]['finding_type'] == 'test_finding'

# Test that BaseDetector cannot be instantiated directly
def test_abstract_class_instantiation():
    """Test that the abstract BaseDetector cannot be instantiated."""
    with pytest.raises(TypeError):
        BaseDetector()
