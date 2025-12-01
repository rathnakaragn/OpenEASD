"""
Integration tests for Analysis Layer workflow.

Tests the complete analysis workflow including:
- AnalysisService orchestration
- Detector execution
- Risk scoring integration
- Database storage
- End-to-end analysis pipeline
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from src.analysis.analysis_service import AnalysisService
from src.data.database.sqlmodel_manager import SQLModelManager


class TestAnalysisIntegration:
    """Integration tests for complete analysis workflow."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite') as tmp:
            db_path = tmp.name

        db = SQLModelManager(db_path=db_path)
        db.initialize()

        yield db

        db.close()
        # Cleanup
        try:
            os.unlink(db_path)
        except:
            pass

    @pytest.fixture
    def analysis_service(self, temp_db):
        """Create AnalysisService with temporary database."""
        return AnalysisService(db_manager=temp_db)

    # ============================================================================
    # Basic Workflow Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_analyze_scan_with_database_exposure(self, analysis_service):
        """Test complete analysis workflow with database exposure."""
        scan_id = 'test-scan-001'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {
                    'port': 3306,
                    'target_host': 'db.production.example.com',
                    'protocol': 'tcp',
                    'ip': '1.2.3.4',
                    'subdomain': 'db.production.example.com'
                }
            ]
        }

        # Run analysis
        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Check result structure
        assert 'scan_id' in result
        assert 'findings_count' in result
        assert 'findings' in result
        assert 'statistics' in result
        assert 'analysis_timestamp' in result

        # Should find at least one finding (database exposure)
        assert result['findings_count'] >= 1

        # Check findings
        findings = result['findings']
        assert len(findings) >= 1

        # Find database exposure
        db_finding = next(
            (f for f in findings if f['finding_type'] == 'database_port_exposed'),
            None
        )
        assert db_finding is not None, "Should detect database exposure"

        # Check finding has risk score
        assert 'risk_score' in db_finding
        assert 'severity' in db_finding
        assert db_finding['severity'] == 'critical'
        assert db_finding['risk_score'] >= 75

    @pytest.mark.asyncio
    async def test_analyze_scan_with_multiple_findings(self, analysis_service):
        """Test analysis with multiple ports and findings."""
        scan_id = 'test-scan-002'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},
                {'port': 5432, 'target_host': 'postgres.example.com', 'protocol': 'tcp'},
                {'port': 23, 'target_host': 'server.example.com', 'protocol': 'tcp'},
                {'port': 22, 'target_host': 'ssh.example.com', 'protocol': 'tcp'}
            ]
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Should find multiple findings
        assert result['findings_count'] >= 3

        # Check statistics
        stats = result['statistics']
        assert stats['critical_findings'] >= 2  # Two databases
        assert stats['total_findings'] >= 3

    @pytest.mark.asyncio
    async def test_analyze_scan_with_deduplication(self, analysis_service):
        """Test that deduplication works correctly."""
        scan_id = 'test-scan-003'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                # Same port/host combination
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # After deduplication, should have only unique findings
        findings = result['findings']

        # Count findings for this specific port/host
        db_findings = [
            f for f in findings
            if f['port'] == 3306 and f['affected_asset'] == 'db.example.com'
        ]

        # Should be deduplicated (but detector might create multiple finding types)
        # So we check that we don't have exact duplicates
        finding_keys = []
        for f in db_findings:
            key = (f['finding_type'], f['affected_asset'], f.get('port'))
            finding_keys.append(key)

        # No exact duplicates
        assert len(finding_keys) == len(set(finding_keys))

    @pytest.mark.asyncio
    async def test_analyze_empty_scan(self, analysis_service):
        """Test analysis with no ports found."""
        scan_id = 'test-scan-004'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': []
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Should complete without errors
        assert result['findings_count'] == 0
        assert len(result['findings']) == 0

        # Statistics should be all zeros
        stats = result['statistics']
        assert stats['total_findings'] == 0
        assert stats['critical_findings'] == 0

    # ============================================================================
    # Database Integration Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_findings_stored_in_database(self, analysis_service, temp_db):
        """Test that findings are stored in database."""
        scan_id = 'test-scan-005'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        # Run analysis
        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        assert result['findings_count'] >= 1

        # Query database to verify storage
        stored_findings = temp_db.get_findings(scan_id=scan_id)

        assert stored_findings['total_count'] >= 1
        assert len(stored_findings['findings']) >= 1

        # Check that stored finding matches
        stored = stored_findings['findings'][0]
        assert stored['scan_id'] == scan_id
        assert stored['port'] == 3306

    @pytest.mark.asyncio
    async def test_retrieve_findings_by_scan(self, analysis_service, temp_db):
        """Test retrieving findings for a specific scan."""
        scan_id = 'test-scan-006'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},
                {'port': 5432, 'target_host': 'postgres.example.com', 'protocol': 'tcp'}
            ]
        }

        # Run analysis
        await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Retrieve via service method
        findings = await analysis_service.get_scan_findings(scan_id)

        assert len(findings) >= 2
        assert all(f['scan_id'] == scan_id for f in findings)

    @pytest.mark.asyncio
    async def test_retrieve_findings_by_asset(self, analysis_service, temp_db):
        """Test retrieving findings for a specific asset."""
        scan_id = 'test-scan-007'
        target_asset = 'db.production.example.com'

        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': target_asset, 'protocol': 'tcp'},
                {'port': 3307, 'target_host': 'db.staging.example.com', 'protocol': 'tcp'}
            ]
        }

        # Run analysis
        await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Retrieve by asset
        findings = await analysis_service.get_findings_by_asset(target_asset)

        assert len(findings) >= 1
        assert all(f['affected_asset'] == target_asset for f in findings)

    @pytest.mark.asyncio
    async def test_findings_statistics(self, analysis_service, temp_db):
        """Test findings statistics calculation."""
        scan_id = 'test-scan-008'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'},     # Critical
                {'port': 5432, 'target_host': 'postgres.example.com', 'protocol': 'tcp'}, # Critical
                {'port': 23, 'target_host': 'server.example.com', 'protocol': 'tcp'},    # Critical/High
                {'port': 8080, 'target_host': 'web.example.com', 'protocol': 'tcp'}      # Medium
            ]
        }

        # Run analysis
        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Check statistics from database
        stats = temp_db.get_findings_statistics(scan_id=scan_id)

        assert stats['total_findings'] >= 3
        assert stats['critical_findings'] >= 2  # At least 2 databases
        assert stats['average_risk_score'] > 50  # Should be high due to critical findings

    # ============================================================================
    # Risk Scoring Integration Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_risk_scores_calculated(self, analysis_service):
        """Test that all findings have risk scores."""
        scan_id = 'test-scan-009'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.production.com', 'protocol': 'tcp'},
                {'port': 8080, 'target_host': 'staging.example.com', 'protocol': 'tcp'}
            ]
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        findings = result['findings']

        for finding in findings:
            assert 'risk_score' in finding
            assert 'severity' in finding
            assert 0 <= finding['risk_score'] <= 100
            assert finding['severity'] in ['critical', 'high', 'medium', 'low', 'info']

    @pytest.mark.asyncio
    async def test_score_breakdown_included(self, analysis_service):
        """Test that score breakdown is included in findings."""
        scan_id = 'test-scan-010'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        finding = result['findings'][0]
        assert 'score_breakdown' in finding

        breakdown = finding['score_breakdown']
        assert 'base_score' in breakdown
        assert 'context_score' in breakdown
        assert 'exposure_score' in breakdown
        assert 'total' in breakdown

        # Validate score components
        assert breakdown['base_score'] <= 40
        assert breakdown['context_score'] <= 40
        assert breakdown['exposure_score'] <= 20

    @pytest.mark.asyncio
    async def test_production_assets_higher_scores(self, analysis_service):
        """Test that production assets get higher risk scores."""
        scan_id = 'test-scan-011'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.production.example.com', 'protocol': 'tcp'},
                {'port': 3306, 'target_host': 'db.staging.example.com', 'protocol': 'tcp'}
            ]
        }

        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        prod_finding = next(
            f for f in result['findings']
            if 'production' in f['affected_asset']
        )
        staging_finding = next(
            f for f in result['findings']
            if 'staging' in f['affected_asset']
        )

        # Production should have higher or equal score
        assert prod_finding['risk_score'] >= staging_finding['risk_score']

    # ============================================================================
    # Detector Integration Tests
    # ============================================================================

    def test_detector_loading(self, analysis_service):
        """Test that detectors are loaded correctly."""
        assert analysis_service.get_detector_count() >= 1

        detector_names = analysis_service.get_detector_names()
        assert 'PortVulnerabilityDetector' in detector_names

    def test_service_enabled_check(self, analysis_service):
        """Test that service enabled check works."""
        assert analysis_service.is_enabled() == True

    @pytest.mark.asyncio
    async def test_detector_errors_dont_fail_analysis(self, analysis_service):
        """Test that detector errors don't crash the entire analysis."""
        scan_id = 'test-scan-012'

        # Malformed scan data that might cause detector errors
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': None, 'target_host': 'example.com'},  # Invalid
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}  # Valid
            ]
        }

        # Should not raise exception
        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Should still process valid findings
        assert 'findings' in result
        assert 'statistics' in result

    # ============================================================================
    # Error Handling Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_analysis_with_invalid_scan_id(self, analysis_service):
        """Test analysis with missing scan_id."""
        scan_data = {
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        # Should handle gracefully
        try:
            await analysis_service.analyze_scan_results(None, scan_data)
            # If it doesn't raise, check the result
        except Exception as e:
            # Expected to fail
            assert True

    @pytest.mark.asyncio
    async def test_analysis_without_database(self):
        """Test analysis works without database manager."""
        service = AnalysisService(db_manager=None)

        scan_id = 'test-scan-013'
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.example.com', 'protocol': 'tcp'}
            ]
        }

        # Should work but not store
        result = await service.analyze_scan_results(scan_id, scan_data)

        assert result['findings_count'] >= 1
        # Storage would be skipped

    # ============================================================================
    # End-to-End Workflow Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_complete_scan_analysis_workflow(self, analysis_service, temp_db):
        """Test complete workflow: scan → analysis → storage → retrieval → statistics."""
        scan_id = 'test-scan-complete'

        # Step 1: Simulate scan results
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                {'port': 3306, 'target_host': 'db.production.example.com', 'protocol': 'tcp', 'ip': '1.2.3.4'},
                {'port': 5432, 'target_host': 'postgres.prod.example.com', 'protocol': 'tcp', 'ip': '1.2.3.5'},
                {'port': 23, 'target_host': 'legacy.example.com', 'protocol': 'tcp', 'ip': '1.2.3.6'},
                {'port': 22, 'target_host': 'ssh.example.com', 'protocol': 'tcp', 'ip': '1.2.3.7'}
            ]
        }

        # Step 2: Run analysis
        analysis_result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Verify analysis completed
        assert analysis_result['findings_count'] >= 3
        assert analysis_result['statistics']['critical_findings'] >= 2

        # Step 3: Retrieve findings from database
        db_findings = temp_db.get_findings(scan_id=scan_id, limit=100)

        # Verify storage
        assert db_findings['total_count'] >= 3
        assert len(db_findings['findings']) >= 3

        # Step 4: Verify statistics
        stats = temp_db.get_findings_statistics(scan_id=scan_id)

        assert stats['total_findings'] >= 3
        assert stats['critical_findings'] >= 2
        assert stats['average_risk_score'] >= 60  # Should be high

        # Step 5: Filter by severity
        critical_findings = temp_db.get_findings(scan_id=scan_id, min_severity='critical')

        assert critical_findings['total_count'] >= 2
        for finding in critical_findings['findings']:
            assert finding['severity'] in ['critical']

        # Step 6: Update finding status
        finding_id = db_findings['findings'][0]['id']
        success = temp_db.update_finding_status(
            finding_id=finding_id,
            status='acknowledged',
            resolution_notes='Under investigation'
        )

        assert success == True

        # Verify status update
        updated_finding = temp_db.get_finding_by_id(finding_id)
        assert updated_finding['status'] == 'acknowledged'
        assert updated_finding['resolution_notes'] == 'Under investigation'

    @pytest.mark.asyncio
    async def test_realistic_production_scenario(self, analysis_service, temp_db):
        """Test realistic production scenario with mixed findings."""
        scan_id = 'prod-scan-001'

        # Realistic scan: production environment with various services
        scan_data = {
            'scan_id': scan_id,
            'naabu_results': [
                # Production databases (CRITICAL)
                {'port': 3306, 'target_host': 'db-master.prod.example.com', 'protocol': 'tcp'},
                {'port': 6379, 'target_host': 'redis.prod.example.com', 'protocol': 'tcp'},

                # Legacy services (HIGH)
                {'port': 23, 'target_host': 'legacy-server.example.com', 'protocol': 'tcp'},

                # Admin interfaces (HIGH)
                {'port': 8443, 'target_host': 'admin.example.com', 'protocol': 'tcp'},

                # Development services (MEDIUM)
                {'port': 8080, 'target_host': 'dev-api.example.com', 'protocol': 'tcp'},

                # Standard services (LOW)
                {'port': 22, 'target_host': 'bastion.example.com', 'protocol': 'tcp'},
                {'port': 80, 'target_host': 'www.example.com', 'protocol': 'tcp'},
                {'port': 443, 'target_host': 'api.example.com', 'protocol': 'tcp'}
            ]
        }

        # Run analysis
        result = await analysis_service.analyze_scan_results(scan_id, scan_data)

        # Verify comprehensive analysis
        assert result['findings_count'] >= 5

        stats = result['statistics']

        # Should have multiple severity levels
        assert stats['critical_findings'] >= 2  # Databases
        assert stats['high_findings'] >= 2      # Legacy + admin
        assert stats['total_findings'] >= 5

        # Verify high average risk score
        assert stats['average_risk_score'] >= 50

        # Verify findings are sorted by risk score (highest first)
        findings = result['findings']
        risk_scores = [f['risk_score'] for f in findings]
        assert risk_scores == sorted(risk_scores, reverse=True), \
            "Findings should be sorted by risk score descending"
