
import pytest
from datetime import datetime
from typing import Optional, Any, Dict
from pydantic import ValidationError as PydanticValidationError
# Import from Data Layer (models moved from Analysis Layer for proper layering)
from src.data.models.finding import Finding, Vulnerability, CVEMapping, FindingGroup


class TestFindingModel:
    """Test cases for the Finding SQLModel."""

    def test_finding_creation_required_fields(self):
        """Test that a Finding instance can be created with only required fields."""
        finding = Finding(
            id="f-001",
            scan_id="s-001",
            finding_type="sqli",
            affected_asset="example.com",
            title="SQL Injection Vulnerability",
            severity="critical",
            risk_score=90,
        )

        assert finding.id == "f-001"
        assert finding.scan_id == "s-001"
        assert finding.finding_type == "sqli"
        assert finding.affected_asset == "example.com"
        assert finding.title == "SQL Injection Vulnerability"
        assert finding.severity == "critical"
        assert finding.risk_score == 90
        assert isinstance(finding.discovered_at, datetime)
        assert isinstance(finding.updated_at, datetime)
        assert finding.status == "open"  # Default value
        assert finding.false_positive is False  # Default value

    def test_finding_creation_all_fields(self):
        """Test that a Finding instance can be created with all fields."""
        now = datetime.utcnow()
        finding = Finding(
            id="f-002",
            scan_id="s-002",
            finding_type="xss",
            affected_asset="sub.example.com",
            port=80,
            protocol="tcp",
            title="Cross-Site Scripting",
            description="Reflected XSS in param 'q'",
            service_name="nginx",
            severity="high",
            risk_score=75,
            confidence_level="high",
            evidence_json='{"param": "q", "payload": "<script>alert(1)</script>"}',
            cwe_id="CWE-79",
            remediation="Input validation and output encoding",
            detector="manual",
            score_breakdown_json='{"base": 50, "context": 20, "exposure": 5}',
            status="acknowledged",
            false_positive=False,
            resolved_at=now,
            resolution_notes="Team is working on it",
            discovered_at=now,
            updated_at=now
        )

        assert finding.id == "f-002"
        assert finding.scan_id == "s-002"
        assert finding.finding_type == "xss"
        assert finding.affected_asset == "sub.example.com"
        assert finding.port == 80
        assert finding.protocol == "tcp"
        assert finding.title == "Cross-Site Scripting"
        assert finding.description == "Reflected XSS in param 'q'"
        assert finding.service_name == "nginx"
        assert finding.severity == "high"
        assert finding.risk_score == 75
        assert finding.confidence_level == "high"
        assert finding.evidence_json == '{"param": "q", "payload": "<script>alert(1)</script>"}'
        assert finding.cwe_id == "CWE-79"
        assert finding.remediation == "Input validation and output encoding"
        assert finding.detector == "manual"
        assert finding.score_breakdown_json == '{"base": 50, "context": 20, "exposure": 5}'
        assert finding.status == "acknowledged"
        assert finding.false_positive is False
        assert finding.resolved_at == now
        assert finding.resolution_notes == "Team is working on it"
        assert finding.discovered_at == now
        assert finding.updated_at == now

    def test_finding_defaults(self):
        """Test default values for optional fields."""
        finding = Finding(
            id="f-003",
            scan_id="s-003",
            finding_type="info_disclosure",
            affected_asset="api.example.com",
            title="Info Disclosure",
            severity="info",
            risk_score=10,
        )
        assert finding.port is None
        assert finding.protocol is None
        assert finding.description is None
        assert finding.service_name is None
        assert finding.confidence_level == "medium"
        assert finding.evidence_json is None
        assert finding.cwe_id is None
        assert finding.remediation is None
        assert finding.detector is None
        assert finding.score_breakdown_json is None
        assert finding.status == "open"
        assert finding.false_positive is False
        assert finding.resolved_at is None
        assert finding.resolution_notes is None

    def test_finding_json_fields(self):
        """Test that JSON fields accept string values."""
        json_data = '{"key": "value", "list": [1, 2, 3]}'
        finding = Finding(
            id="f-004",
            scan_id="s-004",
            finding_type="config_error",
            affected_asset="config.example.com",
            title="Config Error",
            severity="low",
            risk_score=20,
            evidence_json=json_data,
            score_breakdown_json=json_data
        )
        assert finding.evidence_json == json_data
        assert finding.score_breakdown_json == json_data



class TestVulnerabilityModel:
    """Test cases for the Vulnerability SQLModel."""

    def test_vulnerability_creation_required_fields(self):
        """Test that a Vulnerability instance can be created with only required fields."""
        vuln = Vulnerability(
            id="v-001",
            cve_id="CVE-2024-0001",
        )
        assert vuln.id == "v-001"
        assert vuln.cve_id == "CVE-2024-0001"
        assert vuln.severity == "medium"
        assert vuln.exploit_available is False

    def test_vulnerability_creation_all_fields(self):
        """Test that a Vulnerability instance can be created with all fields."""
        now = datetime.utcnow()
        vuln = Vulnerability(
            id="v-002",
            cve_id="CVE-2024-0002",
            description="Remote code execution vulnerability",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-89",
            vulnerability_type="rce",
            affected_products_json='["productA", "productB"]',
            affected_versions="1.0-2.0",
            exploit_available=True,
            exploit_maturity="high",
            publicly_disclosed=True,
            references_json='["http://example.com/ref1"]',
            patch_url="http://example.com/patch",
            advisory_url="http://example.com/advisory",
            discovered_at=now,
            updated_at=now
        )
        assert vuln.id == "v-002"
        assert vuln.cve_id == "CVE-2024-0002"
        assert vuln.description == "Remote code execution vulnerability"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 9.8
        assert vuln.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert vuln.cwe_id == "CWE-89"
        assert vuln.vulnerability_type == "rce"
        assert vuln.affected_products_json == '["productA", "productB"]'
        assert vuln.affected_versions == "1.0-2.0"
        assert vuln.exploit_available is True
        assert vuln.exploit_maturity == "high"
        assert vuln.publicly_disclosed is True
        assert vuln.references_json == '["http://example.com/ref1"]'
        assert vuln.patch_url == "http://example.com/patch"
        assert vuln.advisory_url == "http://example.com/advisory"
        assert vuln.discovered_at == now
        assert vuln.updated_at == now

    def test_vulnerability_defaults(self):
        """Test default values for optional vulnerability fields."""
        vuln = Vulnerability(id="v-003", cve_id="CVE-2024-0003")
        assert vuln.severity == "medium"
        assert vuln.exploit_available is False
        assert vuln.description is None
        assert vuln.cvss_score is None

class TestCVEMappingModel:
    """Test cases for the CVEMapping SQLModel."""

    def test_cve_mapping_creation_required_fields(self):
        """Test that a CVEMapping instance can be created with required fields."""
        mapping = CVEMapping(
            id="map-001",
            finding_id="f-001",
            vulnerability_id="v-001"
        )
        assert mapping.id == "map-001"
        assert mapping.finding_id == "f-001"
        assert mapping.vulnerability_id == "v-001"
        assert mapping.confidence == 50

    def test_cve_mapping_creation_all_fields(self):
        """Test that a CVEMapping instance can be created with all fields."""
        now = datetime.utcnow()
        mapping = CVEMapping(
            id="map-002",
            finding_id="f-002",
            vulnerability_id="v-002",
            confidence="high",
            created_at=now,
            updated_at=now
        )
        assert mapping.id == "map-002"
        assert mapping.finding_id == "f-002"
        assert mapping.vulnerability_id == "v-002"
        assert mapping.confidence == "high"
        assert mapping.created_at == now
        assert mapping.updated_at == now

    def test_cve_mapping_defaults(self):
        """Test default values for optional CVEMapping fields."""
        mapping = CVEMapping(id="map-003", finding_id="f-003", vulnerability_id="v-003")
        assert mapping.confidence == 50

class TestFindingGroupModel:
    """Test cases for the FindingGroup SQLModel."""

    def test_finding_group_creation_required_fields(self):
        """Test that a FindingGroup instance can be created with required fields."""
        group = FindingGroup(
            id="fg-001",
            scan_id="s-001",
            name="Critical Database Findings",
            finding_type="database_exposure"
        )
        assert group.id == "fg-001"
        assert group.scan_id == "s-001"
        assert group.name == "Critical Database Findings"
        assert group.finding_type == "database_exposure"
        assert group.status == "open"

    def test_finding_group_creation_all_fields(self):
        """Test that a FindingGroup instance can be created with all fields."""
        now = datetime.utcnow()
        group = FindingGroup(
            id="fg-002",
            scan_id="s-002",
            name="Web Application Flaws",
            finding_type="xss",
            description="Group of XSS and SQLi findings",
            status="investigating",
            created_at=now,
            updated_at=now
        )
        assert group.id == "fg-002"
        assert group.scan_id == "s-002"
        assert group.name == "Web Application Flaws"
        assert group.finding_type == "xss"
        assert group.description == "Group of XSS and SQLi findings"
        assert group.status == "investigating"
        assert group.created_at == now
        assert group.updated_at == now

    def test_finding_group_defaults(self):
        """Test default values for optional FindingGroup fields."""
        group = FindingGroup(id="fg-003", scan_id="s-003", name="Another Group", finding_type="test")
        assert group.status == "open"
        assert group.description is None
