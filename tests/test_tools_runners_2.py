"""
Comprehensive test suite for security tools runners.
"""

import pytest
from unittest.mock import MagicMock, patch, call
import json
import subprocess
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
                stdout='{"host": "api.example.com"}\n{"host": "www.example.com"}\n{"host": "mail.example.com"}'
            )

            result = run_subfinder('example.com', timeout=300)

            assert isinstance(result, list)
            assert len(result) == 3
            assert 'api.example.com' in result

    def test_subfinder_no_results(self):
        """Test subfinder with no results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            result = run_subfinder('nonexistent.com', timeout=300)

            assert isinstance(result, list)
            assert len(result) == 0

    def test_subfinder_command_construction(self):
        """Test that subfinder command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            run_subfinder('example.com', timeout=300)

            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert 'subfinder' in call_args[0][0]
            assert 'example.com' in call_args[0][0]

    def test_subfinder_tool_error(self):
        """Test error handling when subfinder returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError

            with pytest.raises(Exception, match="Subfinder not found"):
                run_subfinder('example.com', timeout=300)

    def test_subfinder_malformed_json(self):
        """Test handling of malformed JSON output."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='invalid json'
            )

            result = run_subfinder('example.com', timeout=300)
            assert isinstance(result, list)
            assert len(result) == 0


class TestNaabuRunner:
    """Test Naabu port scanning runner."""

    def test_naabu_success(self):
        """Test successful naabu execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='{"ip":"api.example.com","port":443}\n{"ip":"api.example.com","port":80}'
            )

            result = run_naabu(['api.example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 2

    def test_naabu_no_open_ports(self):
        """Test naabu with no open ports."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            result = run_naabu(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 0

    def test_naabu_command_construction(self):
        """Test that naabu command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            run_naabu(['example.com'], timeout=300)

            mock_run.assert_called_once()

    def test_naabu_tool_error(self):
        """Test error handling when naabu returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError

            with pytest.raises(Exception, match="Naabu not found"):
                run_naabu(['example.com'], timeout=300)

    def test_naabu_multiple_ports(self):
        """Test naabu result with multiple open ports."""
        ports_json = ('{"ip": "example.com", "port": 22}\n' 
                      '{"ip": "example.com", "port": 80}\n' 
                      '{"ip": "example.com", "port": 443}\n' 
                      '{"ip": "example.com", "port": 3306}')

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=ports_json
            )

            result = run_naabu(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 4


class TestDnsxRunner:
    """Test Dnsx DNS resolution runner."""

    def test_dnsx_success(self):
        """Test successful dnsx execution."""
        records_json = ('{"host": "example.com", "a": ["93.184.216.34"]}\n' 
                        '{"host": "example.com", "mx": ["mail.example.com"]}')

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=records_json
            )

            result = run_dnsx(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 2

    def test_dnsx_no_records(self):
        """Test dnsx with no results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            result = run_dnsx(['nonexistent.invalid'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 0

    def test_dnsx_command_construction(self):
        """Test that dnsx command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            run_dnsx(['example.com'], timeout=300)

            mock_run.assert_called_once()

    def test_dnsx_tool_error(self):
        """Test error handling when dnsx returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError

            with pytest.raises(Exception, match="dnsx not found"):
                run_dnsx(['example.com'], timeout=300)

    def test_dnsx_multiple_record_types(self):
        """Test dnsx with multiple DNS record types."""
        records = ('{"host": "example.com", "a": ["93.184.216.34"]}\n' 
                   '{"host": "example.com", "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"]}\n' 
                   '{"host": "example.com", "mx": ["mail.example.com"]}\n' 
                   '{"host": "example.com", "ns": ["ns1.example.com"]}\n' 
                   '{"host": "example.com", "txt": ["v=spf1"]}')

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=records
            )

            result = run_dnsx(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 5


class TestHttpxRunner:
    """Test Httpx HTTP probing runner."""

    def test_httpx_success(self):
        """Test successful httpx execution."""
        probes = ('{"url": "http://example.com", "status_code": 200, "content_type": "text/html"}\n' 
                  '{"url": "https://example.com", "status_code": 200, "content_type": "text/html"}')

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=probes
            )

            result = run_httpx(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 2

    def test_httpx_unreachable_target(self):
        """Test httpx with unreachable target."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            result = run_httpx(['unreachable.invalid'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 0

    def test_httpx_command_construction(self):
        """Test that httpx command is constructed correctly."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            run_httpx(['example.com'], timeout=300)

            mock_run.assert_called_once()

    def test_httpx_tool_error(self):
        """Test error handling when httpx returns error."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError

            with pytest.raises(Exception, match="httpx not found"):
                run_httpx(['example.com'], timeout=300)

    def test_httpx_multiple_probes(self):
        """Test httpx with multiple probes."""
        probes = ('{"url": "http://api.example.com", "status_code": 200}\n' 
                  '{"url": "http://www.example.com", "status_code": 301}\n' 
                  '{"url": "https://api.example.com", "status_code": 200}\n' 
                  '{"url": "https://www.example.com", "status_code": 301}')

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=probes
            )

            result = run_httpx(['example.com'], timeout=300)

            assert isinstance(result, list)
            assert len(result) == 4


class TestToolErrorHandling:
    """Test error handling across all tools."""

    def test_timeout_handling(self):
        """Test that timeout is passed correctly to subprocess."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=1)

            with pytest.raises(Exception, match="Subfinder timed out"):
                run_subfinder('example.com', timeout=1)

    def test_subprocess_exception_handling(self):
        """Test handling of subprocess exceptions."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError

            with pytest.raises(Exception, match="Subfinder not found"):
                run_subfinder('example.com', timeout=300)

    def test_json_decode_error_handling(self):
        """Test handling of JSON decode errors."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='not valid json {'
            )

            result = run_subfinder('example.com', timeout=300)
            assert isinstance(result, list)
            assert len(result) == 0

    def test_malformed_output(self):
        """Test handling of malformed tool output."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=None
            )

            with pytest.raises(Exception):
                run_subfinder('example.com', timeout=300)


class TestToolIntegration:
    """Test integration between tool runners."""

    def test_multiple_tools_sequential(self):
        """Test running multiple tools in sequence."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            run_subfinder('example.com', timeout=300)
            run_naabu(['api.example.com'], timeout=300)
            run_dnsx(['example.com'], timeout=300)
            run_httpx(['example.com'], timeout=300)

            assert mock_run.call_count == 4

    def test_tool_data_structures(self):
        """Test that tools return consistent data structures."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=''
            )

            results = [
                run_subfinder('example.com', timeout=300),
                run_naabu(['example.com'], timeout=300),
                run_dnsx(['example.com'], timeout=300),
                run_httpx(['example.com'], timeout=300)
            ]

            for result in results:
                assert isinstance(result, list)
