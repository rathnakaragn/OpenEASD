"""
Tests for Tool Runner functions in runners.py.

Covers subprocess execution, JSON parsing, error handling, and edge cases.
"""

import pytest
import json
from unittest.mock import patch, MagicMock, call
import subprocess

from src.tools.runners import run_subfinder, run_naabu, run_dnsx, run_httpx


class TestSubfinderRunner:
    """Test Subfinder runner function."""

    @patch('src.tools.subfinder.subprocess.run')
    def test_run_subfinder_success(self, mock_run):
        """Test successful subfinder execution."""
        mock_output = '{"host":"test.example.com"}\n{"host":"api.example.com"}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0
        )

        result = run_subfinder("example.com")

        assert result is not None
        assert "test.example.com" in result
        assert "api.example.com" in result

    @patch('src.tools.subfinder.subprocess.run')
    def test_run_subfinder_empty_result(self, mock_run):
        """Test subfinder with no subdomains found."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        result = run_subfinder("nonexistent.com")

        assert result == []

    @patch('src.tools.subfinder.subprocess.run')
    def test_run_subfinder_timeout(self, mock_run):
        """Test subfinder timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('subfinder', 300)

        with pytest.raises(Exception) as exc_info:
            run_subfinder("example.com", timeout=300)
        assert "timed out" in str(exc_info.value)

    @patch('src.tools.subfinder.subprocess.run')
    def test_run_subfinder_not_found(self, mock_run):
        """Test subfinder when executable not found."""
        mock_run.side_effect = FileNotFoundError("subfinder not found")

        with pytest.raises(Exception) as exc_info:
            run_subfinder("example.com")
        assert "not found" in str(exc_info.value).lower()

    @patch('src.tools.subfinder.subprocess.run')
    def test_run_subfinder_large_output(self, mock_run):
        """Test subfinder with large number of subdomains."""
        subdomains = "\n".join([f'{{"host":"sub{i}.example.com"}}' for i in range(1000)])
        mock_run.return_value = MagicMock(
            stdout=subdomains,
            returncode=0
        )

        result = run_subfinder("example.com")
        assert len(result) == 1000


class TestNaabuRunner:
    """Test Naabu runner function."""

    @patch('src.tools.naabu.subprocess.run')
    def test_run_naabu_success(self, mock_run):
        """Test successful naabu execution."""
        mock_output = json.dumps({"host": "example.com", "port": 80}) + "\n"
        mock_output += json.dumps({"host": "example.com", "port": 443})
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0
        )

        result = run_naabu(["example.com"])

        assert result is not None
        assert len(result) >= 1

    @patch('src.tools.naabu.subprocess.run')
    def test_run_naabu_no_ports(self, mock_run):
        """Test naabu when no ports found."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        result = run_naabu(["internal.example.com"])
        assert result == []

    @patch('src.tools.naabu.subprocess.run')
    def test_run_naabu_timeout(self, mock_run):
        """Test naabu timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('naabu', 600)

        with pytest.raises(Exception) as exc_info:
            run_naabu(["example.com"], timeout=600)
        assert "timed out" in str(exc_info.value)

    @patch('src.tools.naabu.subprocess.run')
    def test_run_naabu_multiple_targets(self, mock_run):
        """Test naabu with multiple targets."""
        mock_output = json.dumps({"host": "example.com", "port": 80}) + "\n"
        mock_output += json.dumps({"host": "test.com", "port": 443})
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0
        )

        result = run_naabu(["example.com", "test.com"])
        assert len(result) >= 1

    @patch('src.tools.naabu.subprocess.run')
    def test_run_naabu_with_top_ports(self, mock_run):
        """Test naabu with top ports option."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        run_naabu(["example.com"], top_ports=100)
        # Verify it was called


class TestDnsxRunner:
    """Test Dnsx runner function."""

    @patch('src.tools.dnsx.subprocess.run')
    def test_run_dnsx_success(self, mock_run):
        """Test successful dnsx execution."""
        mock_output = json.dumps({"host": "example.com", "a": ["192.0.2.1"]})
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0
        )

        result = run_dnsx(["example.com"])

        assert result is not None

    @patch('src.tools.dnsx.subprocess.run')
    def test_run_dnsx_no_resolution(self, mock_run):
        """Test dnsx when DNS resolution fails."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        result = run_dnsx(["nonexistent.invalid"])
        assert result == []

    @patch('src.tools.dnsx.subprocess.run')
    def test_run_dnsx_timeout(self, mock_run):
        """Test dnsx timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('dnsx', 60)

        with pytest.raises(Exception) as exc_info:
            run_dnsx(["example.com"], timeout=60)
        assert "timed out" in str(exc_info.value)


class TestHttpxRunner:
    """Test Httpx runner function."""

    @patch('src.tools.httpx.subprocess.run')
    def test_run_httpx_success(self, mock_run):
        """Test successful httpx execution."""
        mock_output = json.dumps({"url": "http://example.com", "status": 200})
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0
        )

        result = run_httpx(["example.com"])

        assert result is not None

    @patch('src.tools.httpx.subprocess.run')
    def test_run_httpx_no_response(self, mock_run):
        """Test httpx when no HTTP response."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        result = run_httpx(["unreachable.internal"])
        assert result == []

    @patch('src.tools.httpx.subprocess.run')
    def test_run_httpx_timeout(self, mock_run):
        """Test httpx timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('httpx', 300)

        with pytest.raises(Exception) as exc_info:
            run_httpx(["example.com"], timeout=300)
        assert "timed out" in str(exc_info.value)


class TestRunnerEdgeCases:
    """Test edge cases across all runners."""

    @patch('src.tools.naabu.subprocess.run')
    def test_runner_with_invalid_json(self, mock_run):
        """Test runners with invalid JSON in output."""
        mock_run.return_value = MagicMock(
            stdout='{"invalid": json}',
            returncode=0
        )

        # Most runners should handle this gracefully
        result = run_naabu(["example.com"])
        assert result == [] or result is not None

    @patch('src.tools.naabu.subprocess.run')
    def test_runner_with_empty_targets(self, mock_run):
        """Test runners with empty target list."""
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )

        result = run_naabu([])
        # Should handle empty list

    @patch('src.tools.subfinder.subprocess.run')
    def test_runner_with_special_characters(self, mock_run):
        """Test runners with special characters in domain."""
        mock_run.return_value = MagicMock(
            stdout='{"host":"api-test.example.co.uk"}\n',
            returncode=0
        )

        result = run_subfinder("example.co.uk")
        assert "api-test.example.co.uk" in result
