"""
Tests for Model Converters.

Covers model-to-dict conversion, JSON parsing, timezone handling, and batch operations.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock

from src.data.converters import (
    ModelConverter,
    ScanConverter,
    ToolResultConverter,
    FindingConverter,
    DomainConverter,
    convert_scan_results,
    convert_findings_with_vulnerabilities
)


class MockModel:
    """Mock SQLModel for testing."""

    # Use class-level model_fields dict like SQLModel
    model_fields = {
        'id': None,
        'name': None,
        'data_json': None,
        'created_at': None,
        'optional_field': None
    }

    def __init__(self, id='123', name='test', data_json='{"key": "value"}',
                 created_at=None, optional_field=None):
        self.id = id
        self.name = name
        self.data_json = data_json
        self.created_at = created_at or datetime(2025, 1, 1, 12, 0, 0)
        self.optional_field = optional_field


class MockScanSession:
    """Mock ScanSession for testing."""
    model_fields = {
        'scan_id': None, 'scan_type': None, 'domains_scanned': None,
        'metadata': None, 'started_at': None, 'completed_at': None,
        'created_at': None, 'status': None
    }

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockSubdomainHistory:
    """Mock SubdomainHistory for testing."""
    model_fields = {
        'id': None, 'subdomain': None, 'apex_domain': None, 'meta_data': None,
        'first_seen': None, 'last_seen': None, 'status': None
    }

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockFinding:
    """Mock Finding for testing."""
    model_fields = {
        'id': None, 'finding_type': None, 'evidence_json': None,
        'score_breakdown_json': None, 'metadata_json': None,
        'first_seen': None, 'last_seen': None, 'resolved_at': None,
        'updated_at': None, 'created_at': None
    }

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockToolResult:
    """Generic mock tool result."""
    def __init__(self, fields, **kwargs):
        self.__class__.model_fields = {f: None for f in fields}
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestModelConverter:
    """Tests for generic ModelConverter."""

    def test_model_to_dict_basic(self):
        """Test basic model conversion."""
        model = MockModel()
        result = ModelConverter.model_to_dict(model)

        assert result['id'] == '123'
        assert result['name'] == 'test'

    def test_model_to_dict_with_json_fields(self):
        """Test conversion with JSON field parsing."""
        model = MockModel(data_json='{"nested": {"key": "value"}}')
        result = ModelConverter.model_to_dict(
            model,
            json_fields={'data_json'}
        )

        assert result['data_json'] == {'nested': {'key': 'value'}}

    def test_model_to_dict_with_invalid_json(self):
        """Test conversion handles invalid JSON gracefully."""
        model = MockModel(data_json='not valid json')
        result = ModelConverter.model_to_dict(
            model,
            json_fields={'data_json'}
        )

        # Should return empty dict for invalid JSON
        assert result['data_json'] == {}

    def test_model_to_dict_with_datetime_fields(self):
        """Test conversion with datetime fields."""
        model = MockModel(created_at=datetime(2025, 6, 15, 10, 30, 0))
        result = ModelConverter.model_to_dict(
            model,
            datetime_fields={'created_at'}
        )

        # Should have converted datetime (IST conversion)
        assert result['created_at'] is not None

    def test_model_to_dict_exclude_none(self):
        """Test conversion excluding None values."""
        model = MockModel(optional_field=None)
        result = ModelConverter.model_to_dict(
            model,
            exclude_none=True
        )

        assert 'optional_field' not in result

    def test_model_to_dict_include_none(self):
        """Test conversion including None values."""
        model = MockModel(optional_field=None)
        result = ModelConverter.model_to_dict(
            model,
            exclude_none=False
        )

        assert 'optional_field' in result
        assert result['optional_field'] is None

    def test_model_to_dict_exclude_fields(self):
        """Test conversion with excluded fields."""
        model = MockModel()
        result = ModelConverter.model_to_dict(
            model,
            exclude_fields={'data_json', 'optional_field'}
        )

        assert 'data_json' not in result
        assert 'optional_field' not in result
        assert 'id' in result
        assert 'name' in result

    def test_model_to_dict_none_model(self):
        """Test conversion with None model returns empty dict."""
        result = ModelConverter.model_to_dict(None)

        assert result == {}

    def test_models_to_list(self):
        """Test batch conversion of models to list."""
        models = [
            MockModel(id='1', name='first'),
            MockModel(id='2', name='second'),
            MockModel(id='3', name='third')
        ]

        result = ModelConverter.models_to_list(models)

        assert len(result) == 3
        assert result[0]['id'] == '1'
        assert result[1]['id'] == '2'
        assert result[2]['id'] == '3'

    def test_models_to_list_with_options(self):
        """Test batch conversion with options."""
        models = [
            MockModel(data_json='{"a": 1}'),
            MockModel(data_json='{"b": 2}')
        ]

        result = ModelConverter.models_to_list(
            models,
            json_fields={'data_json'}
        )

        assert result[0]['data_json'] == {'a': 1}
        assert result[1]['data_json'] == {'b': 2}


class TestScanConverter:
    """Tests for ScanConverter."""

    def test_scan_to_dict(self):
        """Test scan conversion."""
        mock_scan = MockScanSession(
            scan_id='scan-123',
            scan_type='full_scan',
            domains_scanned='["example.com", "test.com"]',
            metadata='{"tool": "subfinder"}',
            started_at=datetime(2025, 1, 1, 10, 0, 0),
            completed_at=None,
            created_at=datetime(2025, 1, 1, 9, 0, 0),
            status='running'
        )

        result = ScanConverter.scan_to_dict(mock_scan)

        assert result['scan_id'] == 'scan-123'
        assert result['domains_scanned'] == ['example.com', 'test.com']
        assert result['metadata'] == {'tool': 'subfinder'}

    def test_subdomain_history_to_dict(self):
        """Test subdomain history conversion."""
        mock_history = MockSubdomainHistory(
            id='hist-123',
            subdomain='api.example.com',
            apex_domain='example.com',
            meta_data='{"source": "subfinder"}',
            first_seen=datetime(2025, 1, 1, 10, 0, 0),
            last_seen=datetime(2025, 1, 2, 10, 0, 0),
            status='new'
        )

        result = ScanConverter.subdomain_history_to_dict(mock_history)

        assert result['subdomain'] == 'api.example.com'
        assert result['meta_data'] == {'source': 'subfinder'}


class TestToolResultConverter:
    """Tests for ToolResultConverter."""

    def test_subfinder_result_to_dict(self):
        """Test subfinder result conversion."""

        class MockSubfinderResult:
            model_fields = {'id': None, 'scan_id': None, 'subdomain': None,
                           'apex_domain': None, 'discovered_at': None}

            def __init__(self):
                self.id = 'result-123'
                self.scan_id = 'scan-456'
                self.subdomain = 'api.example.com'
                self.apex_domain = 'example.com'
                self.discovered_at = datetime(2025, 1, 1, 10, 0, 0)

        result = ToolResultConverter.subfinder_result_to_dict(MockSubfinderResult())

        assert result['subdomain'] == 'api.example.com'

    def test_naabu_result_to_dict(self):
        """Test naabu result conversion."""

        class MockNaabuResult:
            model_fields = {'id': None, 'scan_id': None, 'target_host': None,
                           'port': None, 'protocol': None, 'scanned_at': None}

            def __init__(self):
                self.id = 'result-123'
                self.scan_id = 'scan-456'
                self.target_host = 'example.com'
                self.port = 443
                self.protocol = 'tcp'
                self.scanned_at = datetime(2025, 1, 1, 10, 0, 0)

        result = ToolResultConverter.naabu_result_to_dict(MockNaabuResult())

        assert result['target_host'] == 'example.com'
        assert result['port'] == 443

    def test_amass_result_to_dict(self):
        """Test amass result conversion."""

        class MockAmassResult:
            model_fields = {'id': None, 'scan_id': None, 'subdomain': None,
                           'sources': None, 'discovered_at': None}

            def __init__(self):
                self.id = 'result-123'
                self.scan_id = 'scan-456'
                self.subdomain = 'mail.example.com'
                self.sources = '["dns", "cert"]'
                self.discovered_at = datetime(2025, 1, 1, 10, 0, 0)

        result = ToolResultConverter.amass_result_to_dict(MockAmassResult())

        assert result['subdomain'] == 'mail.example.com'
        assert result['sources'] == ['dns', 'cert']

    def test_nmap_result_to_dict(self):
        """Test nmap result conversion."""

        class MockNmapResult:
            model_fields = {'id': None, 'scan_id': None, 'target_host': None,
                           'port': None, 'service_info': None, 'os_info': None,
                           'scanned_at': None}

            def __init__(self):
                self.id = 'result-123'
                self.scan_id = 'scan-456'
                self.target_host = 'example.com'
                self.port = 22
                self.service_info = '{"name": "ssh", "version": "OpenSSH 8.0"}'
                self.os_info = '{"name": "Linux"}'
                self.scanned_at = datetime(2025, 1, 1, 10, 0, 0)

        result = ToolResultConverter.nmap_result_to_dict(MockNmapResult())

        assert result['service_info'] == {'name': 'ssh', 'version': 'OpenSSH 8.0'}
        assert result['os_info'] == {'name': 'Linux'}


class TestFindingConverter:
    """Tests for FindingConverter."""

    def test_finding_to_dict(self):
        """Test finding conversion."""
        mock_finding = MockFinding(
            id='finding-123',
            finding_type='open_port',
            evidence_json='{"port": 22, "service": "ssh"}',
            score_breakdown_json='{"base": 70, "exposure": 20}',
            metadata_json=None,
            first_seen=datetime(2025, 1, 1, 10, 0, 0),
            last_seen=datetime(2025, 1, 2, 10, 0, 0),
            resolved_at=None,
            updated_at=datetime(2025, 1, 2, 10, 0, 0),
            created_at=datetime(2025, 1, 1, 10, 0, 0)
        )

        result = FindingConverter.finding_to_dict(mock_finding)

        assert result['finding_type'] == 'open_port'
        assert result['evidence_json'] == {'port': 22, 'service': 'ssh'}
        assert result['score_breakdown_json'] == {'base': 70, 'exposure': 20}

    def test_vulnerability_to_dict(self):
        """Test vulnerability conversion."""

        class MockVulnerability:
            model_fields = {
                'id': None, 'cve_id': None, 'cvss_vector': None,
                'affected_versions': None, 'references': None,
                'disclosed_at': None, 'updated_at': None
            }

            def __init__(self):
                self.id = 'vuln-123'
                self.cve_id = 'CVE-2025-1234'
                self.cvss_vector = '{"attackVector": "NETWORK"}'
                self.affected_versions = '["1.0", "1.1", "1.2"]'
                self.references = '["https://nvd.nist.gov"]'
                self.disclosed_at = datetime(2025, 1, 1, 0, 0, 0)
                self.updated_at = datetime(2025, 1, 2, 0, 0, 0)

        result = FindingConverter.vulnerability_to_dict(MockVulnerability())

        assert result['cve_id'] == 'CVE-2025-1234'
        assert result['cvss_vector'] == {'attackVector': 'NETWORK'}
        assert result['affected_versions'] == ['1.0', '1.1', '1.2']


class TestDomainConverter:
    """Tests for DomainConverter."""

    def test_domain_to_dict(self):
        """Test domain conversion."""

        class MockDomain:
            model_fields = {
                'domain': None, 'is_primary': None, 'tags': None,
                'metadata': None, 'last_scan': None, 'created_at': None,
                'updated_at': None
            }

            def __init__(self):
                self.domain = 'example.com'
                self.is_primary = True
                self.tags = '["production", "external"]'
                self.metadata = '{"owner": "security-team"}'
                self.last_scan = datetime(2025, 1, 1, 10, 0, 0)
                self.created_at = datetime(2024, 6, 1, 0, 0, 0)
                self.updated_at = datetime(2025, 1, 1, 10, 0, 0)

        result = DomainConverter.domain_to_dict(MockDomain())

        assert result['domain'] == 'example.com'
        assert result['tags'] == ['production', 'external']
        assert result['metadata'] == {'owner': 'security-team'}


class TestBatchConversionUtilities:
    """Tests for batch conversion utility functions."""

    def test_convert_scan_results(self):
        """Test batch scan conversion."""
        mock_scan1 = MockScanSession(
            scan_id='scan-1',
            domains_scanned='["a.com"]',
            metadata='{}',
            started_at=None,
            completed_at=None,
            created_at=None,
            scan_type='test',
            status='running'
        )

        mock_scan2 = MockScanSession(
            scan_id='scan-2',
            domains_scanned='["b.com"]',
            metadata='{}',
            started_at=None,
            completed_at=None,
            created_at=None,
            scan_type='test',
            status='running'
        )

        result = convert_scan_results([mock_scan1, mock_scan2])

        assert len(result) == 2
        assert result[0]['scan_id'] == 'scan-1'
        assert result[1]['scan_id'] == 'scan-2'

    def test_convert_findings_with_vulnerabilities(self):
        """Test batch finding conversion with vulnerabilities."""

        class MockVuln:
            model_fields = {
                'id': None, 'cve_id': None, 'cvss_vector': None,
                'affected_versions': None, 'references': None,
                'disclosed_at': None, 'updated_at': None
            }

            def __init__(self):
                self.id = 'vuln-1'
                self.cve_id = 'CVE-2025-0001'
                self.cvss_vector = '{}'
                self.affected_versions = '[]'
                self.references = '[]'
                self.disclosed_at = None
                self.updated_at = None

        mock_finding = MockFinding(
            id='finding-1',
            finding_type='vulnerable_service',
            evidence_json='{}',
            score_breakdown_json='{}',
            metadata_json=None,
            first_seen=None,
            last_seen=None,
            resolved_at=None,
            updated_at=None,
            created_at=None
        )
        mock_finding.vulnerabilities = [MockVuln()]

        result = convert_findings_with_vulnerabilities([mock_finding])

        assert len(result) == 1
        assert 'vulnerabilities' in result[0]
        assert len(result[0]['vulnerabilities']) == 1
        assert result[0]['vulnerabilities'][0]['cve_id'] == 'CVE-2025-0001'

    def test_convert_findings_without_vulnerabilities(self):
        """Test batch finding conversion without vulnerabilities."""
        mock_finding = MockFinding(
            id='finding-1',
            finding_type='open_port',
            evidence_json='{}',
            score_breakdown_json='{}',
            metadata_json=None,
            first_seen=None,
            last_seen=None,
            resolved_at=None,
            updated_at=None,
            created_at=None
        )
        # No vulnerabilities attribute

        result = convert_findings_with_vulnerabilities([mock_finding])

        assert len(result) == 1
        assert 'vulnerabilities' not in result[0]
