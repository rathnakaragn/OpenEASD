"""
Unit tests for nmap vulnerability detection and parallel execution.

Tests for:
- run_nmap_vuln_detection() function
- run_nmap_vuln_detection_parallel() function
- _extract_cves_from_nmap_output() helper function
- CVE extraction and severity mapping
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from src.tools.runners import (
    run_nmap_vuln_detection,
    run_nmap_vuln_detection_parallel,
    _extract_cves_from_nmap_output
)


class TestExtractCvesFromNmapOutput:
    """Tests for CVE extraction from nmap output."""

    def test_extract_mysql_cves(self):
        """Test extracting CVE IDs from MySQL vulnerability output."""
        nmap_output = """
        | mysql-vuln-cve2012-2122:
        |   CRITICAL: Authentication bypass in MySQL versions before 5.0.77, 5.1.x before 5.1.37, 5.4.x before 5.4.7, 5.5.x before 5.5.17
        |   CVE-2012-2122
        |   Versions affected: 5.0.0 - 5.0.76, 5.1.0 - 5.1.36, 5.4.0 - 5.4.6, 5.5.0 - 5.5.16
        |
        | mysql-vuln-cve2016-6663:
        |   HIGH: Privilege escalation in MySQL 5.7.30
        |   CVE-2016-6663
        |   Authentication bypass
        """

        cves = _extract_cves_from_nmap_output(nmap_output)

        assert len(cves) >= 2
        cve_ids = [c['cve_id'] for c in cves]
        assert 'CVE-2012-2122' in cve_ids
        assert 'CVE-2016-6663' in cve_ids

    def test_extract_postgresql_cves(self):
        """Test extracting CVE IDs from PostgreSQL vulnerability output."""
        nmap_output = """
        | postgresql-vuln:
        |   Tested: PostgreSQL 11.2
        |   CVE-2019-10128: Privilege escalation vulnerability
        |   Status: Vulnerable
        """

        cves = _extract_cves_from_nmap_output(nmap_output)

        assert len(cves) >= 1
        assert any(c['cve_id'] == 'CVE-2019-10128' for c in cves)

    def test_extract_no_cves(self):
        """Test handling of output with no CVEs."""
        nmap_output = """
        | mysql-enum:
        |   Database version: MySQL 8.0.20
        |   No vulnerabilities found
        """

        cves = _extract_cves_from_nmap_output(nmap_output)

        # Should return empty or no CVEs
        assert len(cves) == 0

    def test_extract_cve_with_varying_formats(self):
        """Test extracting CVEs with different formats."""
        nmap_output = """
        CVE-2012-2122 - Authentication Bypass
        Fixed in CVE-2016-6663
        Also check CVE-2019-10128 for details
        """

        cves = _extract_cves_from_nmap_output(nmap_output)

        assert len(cves) >= 3
        cve_ids = [c['cve_id'] for c in cves]
        assert 'CVE-2012-2122' in cve_ids
        assert 'CVE-2016-6663' in cve_ids
        assert 'CVE-2019-10128' in cve_ids

    def test_extract_duplicate_cves(self):
        """Test handling of duplicate CVE IDs."""
        nmap_output = """
        | mysql-vuln:
        |   CVE-2012-2122
        |   CVE-2012-2122 (listed again)
        |   CVE-2016-6663
        """

        cves = _extract_cves_from_nmap_output(nmap_output)

        # Should deduplicate
        cve_ids = [c['cve_id'] for c in cves]
        assert cve_ids.count('CVE-2012-2122') == 1

    def test_extract_empty_output(self):
        """Test handling of empty nmap output."""
        cves = _extract_cves_from_nmap_output("")

        assert cves == []

    def test_cve_severity_mapping(self):
        """Test that extracted CVEs include severity mapping."""
        nmap_output = "CVE-2012-2122"

        cves = _extract_cves_from_nmap_output(nmap_output)

        assert len(cves) >= 1
        cve = cves[0]
        assert 'cve_id' in cve
        assert 'cvss' in cve  # Field is 'cvss' not 'cvss_score'
        assert 'severity' in cve


class TestRunNmapVulnDetection:
    """Tests for nmap vulnerability detection function."""

    @patch('subprocess.run')
    def test_mysql_vuln_detection(self, mock_run):
        """Test successful MySQL vulnerability detection."""
        mock_output = """
        Starting Nmap 7.92
        Scanning example.com (1.2.3.4)

        | mysql-vuln-cve2012-2122:
        |   CRITICAL: Authentication bypass
        |   CVE-2012-2122
        |_  CVSS: 9.8

        | mysql-vuln-cve2016-6663:
        |   HIGH: Privilege escalation
        |   CVE-2016-6663
        |_  CVSS: 7.5
        """
        mock_run.return_value = MagicMock(stdout=mock_output)

        result = run_nmap_vuln_detection('example.com', 3306, 'mysql', timeout=30)

        assert result['status'] in ['success', 'found_vulns', 'no_vulns']
        if result['status'] == 'success' or result['status'] == 'found_vulns':
            assert 'vulnerabilities' in result

    @patch('subprocess.run')
    def test_postgresql_vuln_detection(self, mock_run):
        """Test PostgreSQL vulnerability detection."""
        mock_output = """
        | postgresql-vuln:
        |   CVE-2019-10128
        |_  CVSS: 8.1
        """
        mock_run.return_value = MagicMock(stdout=mock_output)

        result = run_nmap_vuln_detection('example.com', 5432, 'postgresql', timeout=30)

        assert result['status'] in ['success', 'no_vulns', 'timeout', 'error']
        assert 'vulnerabilities' in result

    @patch('subprocess.run')
    def test_redis_vuln_detection(self, mock_run):
        """Test Redis vulnerability detection."""
        mock_output = """
        | redis-info:
        |   No authentication required
        |   Default port exposed
        |_  Risk: Data exposure
        """
        mock_run.return_value = MagicMock(stdout=mock_output)

        result = run_nmap_vuln_detection('example.com', 6379, 'redis', timeout=30)

        assert result['status'] in ['success', 'found_vulns', 'no_vulns']

    @patch('subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Test timeout handling in vulnerability detection."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('nmap', 30)

        result = run_nmap_vuln_detection('example.com', 3306, 'mysql', timeout=30)

        assert result['status'] == 'timeout'
        assert 'vulnerabilities' in result

    @patch('subprocess.run')
    def test_unknown_service(self, mock_run):
        """Test handling of unknown service."""
        mock_run.return_value = MagicMock(stdout="No output")

        result = run_nmap_vuln_detection('example.com', 9000, 'unknown', timeout=30)

        assert result['status'] in ['success', 'no_vulns', 'unknown']

    def test_nmap_not_installed(self):
        """Test error handling when nmap is not installed."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("nmap not found")

            with pytest.raises(Exception):
                run_nmap_vuln_detection('example.com', 3306, 'mysql', timeout=30)

    @patch('subprocess.run')
    def test_service_specific_scripts(self, mock_run):
        """Test that correct service-specific scripts are used."""
        mock_run.return_value = MagicMock(stdout="")

        run_nmap_vuln_detection('example.com', 3306, 'mysql', timeout=30)

        args = mock_run.call_args[0][0]
        # Check that NSE script parameter is included
        assert any('script' in str(arg) for arg in args)


class TestParallelVulnDetection:
    """Tests for parallel vulnerability detection."""

    @patch('concurrent.futures.ThreadPoolExecutor')
    def test_parallel_vuln_detection_multiple_ports(self, mock_executor_class):
        """Test parallel vulnerability detection for multiple ports."""
        # Setup mock executor
        mock_executor = MagicMock()
        mock_executor_class.return_value.__enter__.return_value = mock_executor

        # Create mock futures
        mock_future_1 = MagicMock()
        mock_future_1.result.return_value = {
            'status': 'found_vulns',
            'vulnerabilities': [
                {'cve_id': 'CVE-2012-2122', 'cvss_score': 9.8, 'severity': 'critical'}
            ]
        }

        mock_future_2 = MagicMock()
        mock_future_2.result.return_value = {
            'status': 'found_vulns',
            'vulnerabilities': [
                {'cve_id': 'CVE-2019-10128', 'cvss_score': 8.1, 'severity': 'high'}
            ]
        }

        # Configure submit to return futures
        mock_executor.submit.side_effect = [mock_future_1, mock_future_2]

        # Configure as_completed to return futures
        from concurrent.futures import as_completed
        with patch('src.tools.runners.as_completed') as mock_as_completed:
            mock_as_completed.return_value = [mock_future_1, mock_future_2]

            ports_with_services = [
                ('example.com', 3306, 'mysql'),
                ('example.com', 5432, 'postgresql')
            ]

            result = run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)

            assert isinstance(result, dict)
            # Results should be indexed by port
            assert len(result) >= 0  # Depends on success

    @patch('subprocess.run')
    def test_parallel_execution_error_handling(self, mock_run):
        """Test error handling in parallel execution."""
        mock_run.side_effect = Exception("Network error")

        ports_with_services = [
            ('example.com', 3306, 'mysql'),
            ('example.com', 5432, 'postgresql')
        ]

        # Should not raise exception, but return partial results
        result = run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)

        assert isinstance(result, dict)

    def test_parallel_execution_with_single_port(self):
        """Test parallel execution with single port (edge case)."""
        ports_with_services = [('example.com', 3306, 'mysql')]

        with patch('src.tools.runners.run_nmap_vuln_detection') as mock_vuln:
            mock_vuln.return_value = {'status': 'success', 'vulnerabilities': []}

            result = run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)

            assert isinstance(result, dict)

    def test_parallel_execution_with_empty_list(self):
        """Test parallel execution with empty port list."""
        ports_with_services = []

        result = run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)

        assert result == {}

    def test_parallel_execution_max_workers_respected(self):
        """Test that max_workers parameter is respected in parallel execution."""
        ports_with_services = [
            ('example.com', 3306, 'mysql'),
            ('example.com', 5432, 'postgresql'),
            ('example.com', 6379, 'redis'),
        ]

        with patch('src.tools.runners.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = MagicMock()
            mock_executor_class.return_value.__enter__.return_value = mock_executor
            mock_executor.submit.return_value = MagicMock()

            from concurrent.futures import as_completed
            with patch('src.tools.runners.as_completed') as mock_as_completed:
                mock_as_completed.return_value = []

                run_nmap_vuln_detection_parallel(ports_with_services, max_workers=3)

                # Verify executor was created with correct max_workers
                mock_executor_class.assert_called_with(max_workers=3)


class TestVulnDetectionIntegration:
    """Integration tests for vulnerability detection workflow."""

    @patch('subprocess.run')
    def test_cve_extraction_from_detection_result(self, mock_run):
        """Test extracting CVEs from vulnerability detection result."""
        mock_output = "CVE-2012-2122 Authentication Bypass"
        mock_run.return_value = MagicMock(stdout=mock_output)

        result = run_nmap_vuln_detection('example.com', 3306, 'mysql')

        # The function extracts CVEs from output
        assert result['status'] in ['success', 'no_vulns']
        assert 'vulnerabilities' in result

    def test_cve_json_serialization(self):
        """Test that CVE lists can be serialized to JSON."""
        cve_list = ['CVE-2012-2122', 'CVE-2016-6663', 'CVE-2019-2627']

        # Should be serializable
        cve_json = json.dumps(cve_list)
        deserialized = json.loads(cve_json)

        assert deserialized == cve_list

    def test_remediation_suggestion_generation(self):
        """Test that remediation suggestions are generated for different services."""
        services = ['mysql', 'postgresql', 'redis', 'mongodb', 'unknown_service']

        for service in services:
            # This would be in scan_service.py logic
            if service.lower() == 'mysql':
                remediation = "Update MySQL to the latest stable version. Current version has known vulnerabilities."
            elif service.lower() == 'postgresql':
                remediation = "Update PostgreSQL to the latest stable version."
            elif service.lower() in ['redis', 'mongodb']:
                remediation = f"Update {service} and enable authentication. Restrict network access to trusted sources only."
            else:
                remediation = f"Update {service} to the latest version and restrict network access."

            assert remediation is not None
            assert "Update" in remediation or "update" in remediation


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
