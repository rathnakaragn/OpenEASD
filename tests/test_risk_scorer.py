"""
Unit tests for RiskScorer.

Tests the deterministic risk scoring algorithm including:
- Base score calculation
- Context score calculation
- Exposure score calculation
- Severity mapping
- Score breakdown
"""

import pytest
from src.analysis.scoring.risk_scorer import RiskScorer


class TestRiskScorer:
    """Test suite for RiskScorer class."""

    @pytest.fixture
    def scorer(self):
        """Create RiskScorer instance."""
        return RiskScorer()

    # ============================================================================
    # Base Score Tests
    # ============================================================================

    def test_base_score_database_exposure(self, scorer):
        """Test base score for database exposure (should be 40 - highest)."""
        finding = {
            'finding_type': 'database_port_exposed',
            'affected_asset': 'db.example.com'
        }
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 40, "Database exposure should have max base score"

    def test_base_score_high_risk_port(self, scorer):
        """Test base score for high-risk port exposure."""
        finding = {
            'finding_type': 'high_risk_port_exposed',
            'affected_asset': 'api.example.com'
        }
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 33, "High-risk port should have base score of 33"

    def test_base_score_medium_risk_port(self, scorer):
        """Test base score for medium-risk port exposure."""
        finding = {
            'finding_type': 'medium_risk_port_exposed',
            'affected_asset': 'web.example.com'
        }
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 22, "Medium-risk port should have base score of 22"

    def test_base_score_unknown_finding(self, scorer):
        """Test base score for unknown finding type (should use defaults)."""
        finding = {
            'finding_type': 'unknown_vulnerability',
            'affected_asset': 'test.example.com'
        }
        base_score = scorer._calculate_base_score(finding)
        assert 0 <= base_score <= 40, "Base score should be in valid range"

    def test_base_score_keywords(self, scorer):
        """Test base score adjustment based on keywords in finding type."""
        # Database keyword
        finding = {'finding_type': 'custom_database_issue', 'affected_asset': 'test.com'}
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 38, "Database keyword should give high score"

        # Exposed keyword
        finding = {'finding_type': 'custom_exposed_service', 'affected_asset': 'test.com'}
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 30, "Exposed keyword should give high score"

        # Discovered keyword
        finding = {'finding_type': 'service_discovered', 'affected_asset': 'test.com'}
        base_score = scorer._calculate_base_score(finding)
        assert base_score == 10, "Discovered keyword should give low score"

    # ============================================================================
    # Context Score Tests
    # ============================================================================

    def test_context_score_production_asset(self, scorer):
        """Test context score for production assets."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'api.production.example.com'
        }
        context_score = scorer._calculate_context_score(finding)
        assert context_score >= 20, "Production asset should increase context score"

    def test_context_score_staging_asset(self, scorer):
        """Test context score for staging assets."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'staging.example.com'
        }
        context_score = scorer._calculate_context_score(finding)
        assert context_score == 5, "Staging asset should have lower context score"

    def test_context_score_database_port(self, scorer):
        """Test context score for database ports."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'db.example.com',
            'port': 3306  # MySQL
        }
        context_score = scorer._calculate_context_score(finding)
        assert context_score >= 15, "Database port should increase context score"

    def test_context_score_admin_interface(self, scorer):
        """Test context score for admin interfaces."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'admin.example.com'
        }
        context_score = scorer._calculate_context_score(finding)
        assert context_score >= 10, "Admin interface should increase context score"

    def test_context_score_combined(self, scorer):
        """Test context score with multiple factors."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'api.production.example.com',
            'port': 5432  # PostgreSQL
        }
        context_score = scorer._calculate_context_score(finding)
        assert context_score >= 35, "Combined factors should give high context score"
        assert context_score <= 40, "Context score should not exceed maximum"

    # ============================================================================
    # Exposure Score Tests
    # ============================================================================

    def test_exposure_score_public_asset(self, scorer):
        """Test exposure score for publicly accessible assets."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'public.example.com'
        }
        exposure_score = scorer._calculate_exposure_score(finding)
        assert exposure_score >= 15, "Public asset should have high exposure score"

    def test_exposure_score_private_asset(self, scorer):
        """Test exposure score for private assets."""
        # Localhost
        finding = {'finding_type': 'test', 'affected_asset': '127.0.0.1'}
        score = scorer._calculate_exposure_score(finding)
        assert score < 15, "Localhost should have low exposure score"

        # Private IP
        finding = {'finding_type': 'test', 'affected_asset': '10.0.0.1'}
        score = scorer._calculate_exposure_score(finding)
        assert score < 15, "Private IP should have low exposure score"

        # Internal domain
        finding = {'finding_type': 'test', 'affected_asset': 'server.internal'}
        score = scorer._calculate_exposure_score(finding)
        assert score < 15, "Internal domain should have low exposure score"

    def test_exposure_score_active_service(self, scorer):
        """Test exposure score for active services."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'api.example.com',
            'status': 'active',
            'port': 443
        }
        exposure_score = scorer._calculate_exposure_score(finding)
        assert exposure_score >= 20, "Active service with port should have high exposure"

    def test_is_publicly_accessible(self, scorer):
        """Test public accessibility detection."""
        # Public
        assert scorer._is_publicly_accessible('example.com') == True
        assert scorer._is_publicly_accessible('api.example.com') == True
        assert scorer._is_publicly_accessible('8.8.8.8') == True

        # Private
        assert scorer._is_publicly_accessible('localhost') == False
        assert scorer._is_publicly_accessible('127.0.0.1') == False
        assert scorer._is_publicly_accessible('10.0.0.1') == False
        assert scorer._is_publicly_accessible('192.168.1.1') == False
        assert scorer._is_publicly_accessible('172.16.0.1') == False
        assert scorer._is_publicly_accessible('server.local') == False
        assert scorer._is_publicly_accessible('app.internal') == False

    # ============================================================================
    # Risk Score Calculation Tests
    # ============================================================================

    def test_calculate_risk_score_critical_finding(self, scorer):
        """Test risk score for critical finding."""
        finding = {
            'finding_type': 'database_port_exposed',
            'affected_asset': 'prod-db.example.com',
            'port': 3306,
            'status': 'active'
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert risk_score >= 80, "Critical finding should have score >= 80"
        assert risk_score <= 100, "Risk score should not exceed 100"

    def test_calculate_risk_score_high_finding(self, scorer):
        """Test risk score for high severity finding."""
        finding = {
            'finding_type': 'high_risk_port_exposed',
            'affected_asset': 'api.production.com',
            'port': 23,  # Telnet
            'status': 'active'
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert 60 <= risk_score < 80, "High finding should have score in 60-79 range"

    def test_calculate_risk_score_medium_finding(self, scorer):
        """Test risk score for medium severity finding."""
        finding = {
            'finding_type': 'medium_risk_port_exposed',
            'affected_asset': 'staging.example.com',
            'port': 8080
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert 40 <= risk_score < 60, "Medium finding should have score in 40-59 range"

    def test_calculate_risk_score_low_finding(self, scorer):
        """Test risk score for low severity finding."""
        finding = {
            'finding_type': 'subdomain_discovered',
            'affected_asset': 'test.example.com'
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert 20 <= risk_score < 40, "Low finding should have score in 20-39 range"

    def test_calculate_risk_score_bounds(self, scorer):
        """Test that risk scores stay within 0-100 bounds."""
        # Minimal finding
        finding = {
            'finding_type': 'info_only',
            'affected_asset': '192.168.1.1'  # Private IP
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert 0 <= risk_score <= 100, "Risk score should be within bounds"

        # Maximal finding
        finding = {
            'finding_type': 'database_port_exposed',
            'affected_asset': 'prod-api-db.example.com',
            'port': 3306,
            'status': 'active',
            'response_code': 200
        }
        risk_score = scorer.calculate_risk_score(finding)
        assert 0 <= risk_score <= 100, "Risk score should be within bounds"

    # ============================================================================
    # Severity Mapping Tests
    # ============================================================================

    def test_map_score_to_severity_critical(self, scorer):
        """Test severity mapping for critical range."""
        assert scorer.map_score_to_severity(100) == 'critical'
        assert scorer.map_score_to_severity(90) == 'critical'
        assert scorer.map_score_to_severity(80) == 'critical'

    def test_map_score_to_severity_high(self, scorer):
        """Test severity mapping for high range."""
        assert scorer.map_score_to_severity(79) == 'high'
        assert scorer.map_score_to_severity(70) == 'high'
        assert scorer.map_score_to_severity(60) == 'high'

    def test_map_score_to_severity_medium(self, scorer):
        """Test severity mapping for medium range."""
        assert scorer.map_score_to_severity(59) == 'medium'
        assert scorer.map_score_to_severity(50) == 'medium'
        assert scorer.map_score_to_severity(40) == 'medium'

    def test_map_score_to_severity_low(self, scorer):
        """Test severity mapping for low range."""
        assert scorer.map_score_to_severity(39) == 'low'
        assert scorer.map_score_to_severity(30) == 'low'
        assert scorer.map_score_to_severity(20) == 'low'

    def test_map_score_to_severity_info(self, scorer):
        """Test severity mapping for info range."""
        assert scorer.map_score_to_severity(19) == 'info'
        assert scorer.map_score_to_severity(10) == 'info'
        assert scorer.map_score_to_severity(0) == 'info'

    # ============================================================================
    # Score Finding Tests (Complete Workflow)
    # ============================================================================

    def test_score_finding_complete(self, scorer):
        """Test complete scoring workflow with all fields."""
        finding = {
            'finding_type': 'database_port_exposed',
            'affected_asset': 'db.production.example.com',
            'port': 5432,
            'protocol': 'tcp',
            'title': 'PostgreSQL Database Exposed',
            'description': 'Database accessible from internet'
        }

        scored_finding = scorer.score_finding(finding)

        # Check all expected fields are present
        assert 'risk_score' in scored_finding
        assert 'severity' in scored_finding
        assert 'score_breakdown' in scored_finding

        # Check score breakdown
        breakdown = scored_finding['score_breakdown']
        assert 'base_score' in breakdown
        assert 'context_score' in breakdown
        assert 'exposure_score' in breakdown
        assert 'total' in breakdown

        # Check values
        assert scored_finding['risk_score'] == breakdown['total']
        assert breakdown['base_score'] <= 40
        assert breakdown['context_score'] <= 40
        assert breakdown['exposure_score'] <= 20

        # Check severity mapping
        assert scored_finding['severity'] in ['critical', 'high', 'medium', 'low', 'info']

    def test_score_finding_preserves_original(self, scorer):
        """Test that scoring preserves original finding data."""
        finding = {
            'finding_type': 'test_finding',
            'affected_asset': 'test.example.com',
            'custom_field': 'custom_value'
        }

        scored_finding = scorer.score_finding(finding)

        # Original fields should be preserved
        assert scored_finding['finding_type'] == finding['finding_type']
        assert scored_finding['affected_asset'] == finding['affected_asset']
        assert scored_finding['custom_field'] == finding['custom_field']

    # ============================================================================
    # Confidence Level Tests
    # ============================================================================

    def test_get_confidence_level_high(self, scorer):
        """Test high confidence level detection."""
        finding = {
            'finding_type': 'database_port_exposed',
            'verified': True,
            'evidence': {'port': 3306, 'banner': 'MySQL'}
        }
        confidence = scorer.get_confidence_level(finding)
        assert confidence == 'high', "Verified finding with evidence should be high confidence"

    def test_get_confidence_level_medium(self, scorer):
        """Test medium confidence level detection."""
        # Has evidence but not verified
        finding = {
            'finding_type': 'database_port_exposed',
            'evidence': {'port': 3306}
        }
        confidence = scorer.get_confidence_level(finding)
        assert confidence == 'medium', "Finding with evidence should be medium confidence"

        # Known pattern but no evidence
        finding = {
            'finding_type': 'database_port_exposed'
        }
        confidence = scorer.get_confidence_level(finding)
        assert confidence == 'medium', "Known finding type should be medium confidence"

    def test_get_confidence_level_low(self, scorer):
        """Test low confidence level detection."""
        finding = {
            'finding_type': 'unknown_vulnerability',
            'affected_asset': 'test.com'
        }
        confidence = scorer.get_confidence_level(finding)
        assert confidence == 'low', "Unknown finding without evidence should be low confidence"

    # ============================================================================
    # Edge Cases and Validation
    # ============================================================================

    def test_score_finding_missing_fields(self, scorer):
        """Test scoring with minimal fields."""
        finding = {
            'finding_type': 'test',
            'affected_asset': 'test.com'
        }
        scored_finding = scorer.score_finding(finding)

        assert 'risk_score' in scored_finding
        assert 'severity' in scored_finding
        assert 0 <= scored_finding['risk_score'] <= 100

    def test_score_deterministic(self, scorer):
        """Test that scoring is deterministic."""
        finding = {
            'finding_type': 'database_port_exposed',
            'affected_asset': 'db.example.com',
            'port': 3306
        }

        score1 = scorer.calculate_risk_score(finding)
        score2 = scorer.calculate_risk_score(finding)
        score3 = scorer.calculate_risk_score(finding)

        assert score1 == score2 == score3, "Risk scores should be deterministic"

    def test_different_databases_same_score(self, scorer):
        """Test that different database ports get similar critical scores."""
        databases = [
            {'port': 3306, 'name': 'MySQL'},
            {'port': 5432, 'name': 'PostgreSQL'},
            {'port': 27017, 'name': 'MongoDB'},
            {'port': 6379, 'name': 'Redis'}
        ]

        scores = []
        for db in databases:
            finding = {
                'finding_type': 'database_port_exposed',
                'affected_asset': 'db.production.com',
                'port': db['port'],
                'status': 'active'
            }
            scores.append(scorer.calculate_risk_score(finding))

        # All database exposures should have similar critical scores
        assert all(score >= 75 for score in scores), "All databases should be critical"
        assert max(scores) - min(scores) <= 10, "Database scores should be similar"
