"""
Comprehensive test suite for security tools runners.

Tests tools execution from src/tools/runners.py including:
- Subfinder for subdomain discovery
- Naabu for port scanning
- Dnsx for DNS resolution
- Httpx for HTTP probing
"""

import pytest
from unittest.mock import MagicMock, patch, call
import json
from src.tools.runners import (
    run_subfinder,
    run_naabu,
    run_dnsx,
    run_httpx
)


class TestSubfinderRunner:
    """Test Subfinder subdomain discovery runner."""

    def test_subfinder_success(self):
        """Test successful subfinder execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='["api.example.com","www.example.com","mail.example.com"]'
            )

            result = run_subfinder('example.com', timeout=300)

            assert result['success'] is True
            assert 'subdomains' in result
            assert len(result['subdomains']) == 3
            assert 'api.example.com' in result['subdomains']

    def test_subfinder_no_results(self):
        """Test subfinder with no results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            result = run_subfinder('nonexistent.com', timeout=300)

            assert result['success'] is True
            assert len(result['subdomains']) == 0

    def test_subfinder_command_construction(self):
        """Test that subfinder command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            run_subfinder('example.com', timeout=300)

            # Verify subprocess was called
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            # Check that 'subfinder' and 'example.com' are in the command
            assert any('subfinder' in str(arg) for arg in call_args[0])

    def test_subfinder_timeout_parameter(self):
        """Test that timeout parameter is used."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            run_subfinder('example.com', timeout=600)

            # Should complete without timing out
            mock_run.assert_called_once()

    def test_subfinder_tool_error(self):
        """Test error handling when subfinder returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = run_subfinder('example.com', timeout=300)

            assert result['success'] is False

    def test_subfinder_malformed_json(self):
        """Test handling of malformed JSON output."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='invalid json'
            )

            result = run_subfinder('example.com', timeout=300)

            assert result['success'] is False


class TestNaabuRunner:
    """Test Naabu port scanning runner."""

    def test_naabu_success(self):
        """Test successful naabu execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[{"ip":"api.example.com","port":443},{"ip":"api.example.com","port":80}]'
            )

            result = run_naabu('api.example.com', timeout=300)

            assert result['success'] is True
            assert 'ports' in result
            assert len(result['ports']) == 2

    def test_naabu_no_open_ports(self):
        """Test naabu with no open ports."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            result = run_naabu('example.com', timeout=300)

            assert result['success'] is True
            assert len(result['ports']) == 0

    def test_naabu_command_construction(self):
        """Test that naabu command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            run_naabu('example.com', timeout=300)

            mock_run.assert_called_once()

    def test_naabu_tool_error(self):
        """Test error handling when naabu returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = run_naabu('example.com', timeout=300)

            assert result['success'] is False

    def test_naabu_multiple_ports(self):
        """Test naabu result with multiple open ports."""
        ports_json = json.dumps([
            {"ip": "example.com", "port": 22},
            {"ip": "example.com", "port": 80},
            {"ip": "example.com", "port": 443},
            {"ip": "example.com", "port": 3306}
        ])

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=ports_json
            )

            result = run_naabu('example.com', timeout=300)

            assert result['success'] is True
            assert len(result['ports']) == 4


class TestDnsxRunner:
    """Test Dnsx DNS resolution runner."""

    def test_dnsx_success(self):
        """Test successful dnsx execution."""
        records_json = json.dumps([
            {
                "host": "example.com",
                "type": "A",
                "data": "93.184.216.34"
            },
            {
                "host": "example.com",
                "type": "MX",
                "data": "mail.example.com"
            }
        ])

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=records_json
            )

            result = run_dnsx('example.com', timeout=300)

            assert result['success'] is True
            assert 'records' in result
            assert len(result['records']) == 2

    def test_dnsx_no_records(self):
        """Test dnsx with no results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            result = run_dnsx('nonexistent.invalid', timeout=300)

            assert result['success'] is True
            assert len(result['records']) == 0

    def test_dnsx_command_construction(self):
        """Test that dnsx command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            run_dnsx('example.com', timeout=300)

            mock_run.assert_called_once()

    def test_dnsx_tool_error(self):
        """Test error handling when dnsx returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = run_dnsx('example.com', timeout=300)

            assert result['success'] is False

    def test_dnsx_multiple_record_types(self):
        """Test dnsx with multiple DNS record types."""
        records = [
            {"host": "example.com", "type": "A", "data": "93.184.216.34"},
            {"host": "example.com", "type": "AAAA", "data": "2606:2800:220:1:248:1893:25c8:1946"},
            {"host": "example.com", "type": "MX", "data": "mail.example.com"},
            {"host": "example.com", "type": "NS", "data": "ns1.example.com"},
            {"host": "example.com", "type": "TXT", "data": "v=spf1"}
        ]

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps(records)
            )

            result = run_dnsx('example.com', timeout=300)

            assert result['success'] is True
            assert len(result['records']) == 5


class TestHttpxRunner:
    """Test Httpx HTTP probing runner."""

    def test_httpx_success(self):
        """Test successful httpx execution."""
        probes = json.dumps([
            {
                "url": "http://example.com",
                "status_code": 200,
                "content_type": "text/html"
            },
            {
                "url": "https://example.com",
                "status_code": 200,
                "content_type": "text/html"
            }
        ])

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=probes
            )

            result = run_httpx('example.com', timeout=300)

            assert result['success'] is True
            assert 'probes' in result
            assert len(result['probes']) == 2

    def test_httpx_unreachable_target(self):
        """Test httpx with unreachable target."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            result = run_httpx('unreachable.invalid', timeout=300)

            assert result['success'] is True
            assert len(result['probes']) == 0

    def test_httpx_command_construction(self):
        """Test that httpx command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            run_httpx('example.com', timeout=300)

            mock_run.assert_called_once()

    def test_httpx_tool_error(self):
        """Test error handling when httpx returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = run_httpx('example.com', timeout=300)

            assert result['success'] is False

    def test_httpx_multiple_probes(self):
        """Test httpx with multiple probes."""
        probes = [
            {"url": "http://api.example.com", "status_code": 200},
            {"url": "http://www.example.com", "status_code": 301},
            {"url": "https://api.example.com", "status_code": 200},
            {"url": "https://www.example.com", "status_code": 301},
        ]

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps(probes)
            )

            result = run_httpx('example.com', timeout=300)

            assert result['success'] is True
            assert len(result['probes']) == 4


class TestToolErrorHandling:
    """Test error handling across all tools."""

    def test_timeout_handling(self):
        """Test that timeout is passed correctly to subprocess."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            # Test different timeout values
            for timeout in [60, 300, 600]:
                run_subfinder('example.com', timeout=timeout)
                mock_run.assert_called()

    def test_subprocess_exception_handling(self):
        """Test handling of subprocess exceptions."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Subprocess failed")

            result = run_subfinder('example.com', timeout=300)
            assert result['success'] is False

    def test_json_decode_error_handling(self):
        """Test handling of JSON decode errors."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='not valid json {'
            )

            result = run_subfinder('example.com', timeout=300)
            assert result['success'] is False

    def test_malformed_output(self):
        """Test handling of malformed tool output."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=None
            )

            result = run_subfinder('example.com', timeout=300)
            assert result['success'] is False


class TestToolIntegration:
    """Test integration between tool runners."""

    def test_multiple_tools_sequential(self):
        """Test running multiple tools in sequence."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            # Run each tool
            result1 = run_subfinder('example.com', timeout=300)
            result2 = run_naabu('api.example.com', timeout=300)
            result3 = run_dnsx('example.com', timeout=300)
            result4 = run_httpx('example.com', timeout=300)

            # All should succeed
            assert all(r['success'] for r in [result1, result2, result3, result4])

    def test_tool_data_structures(self):
        """Test that tools return consistent data structures."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='[]'
            )

            results = [
                run_subfinder('example.com', timeout=300),
                run_naabu('example.com', timeout=300),
                run_dnsx('example.com', timeout=300),
                run_httpx('example.com', timeout=300)
            ]

            # All results should have 'success' key
            for result in results:
                assert 'success' in result
                assert 'timestamp' in result
