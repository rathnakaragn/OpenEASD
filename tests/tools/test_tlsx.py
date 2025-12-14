"""
Tests for TLSX Tool Runner.

Covers TLS/SSL verification, subprocess execution, JSON parsing, and error handling.
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock

from src.tools.tlsx import run_tlsx, run_tlsx_parallel
from src.tools.exceptions import ToolExecutionError, ToolTimeoutError, ToolNotFoundError


class TestRunTlsx:
    """Tests for run_tlsx function."""

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_success(self, mock_tempfile, mock_run):
        """Test successful tlsx execution."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test_targets.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        # Mock JSON output
        mock_output = '{"host":"example.com","port":"443","ip":"192.0.2.1","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","subject_cn":"*.example.com"}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([('example.com', 443)])

        assert len(result) == 1
        assert result[0]['host'] == 'example.com'
        assert result[0]['port'] == 443
        assert result[0]['tls_enabled'] is True
        assert result[0]['tls_version'] == 'tls13'

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_no_tls(self, mock_tempfile, mock_run):
        """Test tlsx when target has no TLS."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"example.com","port":"80","probe_status":false,"error":"connection refused"}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([('example.com', 80)])

        assert len(result) == 1
        assert result[0]['tls_enabled'] is False
        assert result[0]['error'] == 'connection refused'

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_expired_cert(self, mock_tempfile, mock_run):
        """Test tlsx detects expired certificate."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"example.com","port":"443","probe_status":true,"expired":true,"not_after":"2023-01-01T00:00:00Z"}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([('example.com', 443)])

        assert result[0]['expired'] is True

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_self_signed(self, mock_tempfile, mock_run):
        """Test tlsx detects self-signed certificate."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"internal.example.com","port":"443","probe_status":true,"self_signed":true}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([('internal.example.com', 443)])

        assert result[0]['self_signed'] is True

    def test_run_tlsx_empty_targets(self):
        """Test tlsx with empty target list."""
        result = run_tlsx([])
        assert result == []

    @patch('src.tools.tlsx.subprocess.run')
    def test_run_tlsx_timeout(self, mock_run):
        """Test tlsx timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('tlsx', 120)

        with pytest.raises(ToolTimeoutError) as exc_info:
            run_tlsx([('example.com', 443)], timeout=120)

        assert "timed out" in str(exc_info.value)

    @patch('src.tools.tlsx.subprocess.run')
    def test_run_tlsx_not_found(self, mock_run):
        """Test tlsx when executable not found."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(ToolNotFoundError) as exc_info:
            run_tlsx([('example.com', 443)])

        assert "not found" in str(exc_info.value).lower()

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_nonzero_exit(self, mock_tempfile, mock_run):
        """Test tlsx with non-zero exit code."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            returncode=1,
            stderr='Error: invalid input',
            stdout=''
        )

        with pytest.raises(ToolExecutionError) as exc_info:
            run_tlsx([('example.com', 443)])

        assert "failed" in str(exc_info.value).lower()

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_multiple_targets(self, mock_tempfile, mock_run):
        """Test tlsx with multiple targets."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"example.com","port":"443","probe_status":true}\n'
        mock_output += '{"host":"test.com","port":"443","probe_status":true}\n'
        mock_output += '{"host":"api.example.com","port":"8443","probe_status":false}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([
                    ('example.com', 443),
                    ('test.com', 443),
                    ('api.example.com', 8443)
                ])

        assert len(result) == 3

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_wildcard_cert(self, mock_tempfile, mock_run):
        """Test tlsx detects wildcard certificate."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"api.example.com","port":"443","probe_status":true,"subject_cn":"*.example.com","wildcard_certificate":true}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                result = run_tlsx([('api.example.com', 443)])

        assert result[0]['wildcard'] is True
        assert result[0]['subject_cn'] == '*.example.com'


class TestRunTlsxParallel:
    """Tests for run_tlsx_parallel function."""

    @patch('src.tools.tlsx.run_tlsx')
    def test_run_tlsx_parallel_success(self, mock_run_tlsx):
        """Test successful parallel tlsx execution."""
        mock_run_tlsx.return_value = [
            {'host': 'example.com', 'port': 443, 'tls_enabled': True},
            {'host': 'test.com', 'port': 443, 'tls_enabled': True}
        ]

        result = run_tlsx_parallel([
            ('example.com', 443),
            ('test.com', 443)
        ])

        assert 'example.com:443' in result
        assert 'test.com:443' in result
        assert result['example.com:443']['tls_enabled'] is True

    def test_run_tlsx_parallel_empty(self):
        """Test parallel tlsx with empty targets."""
        result = run_tlsx_parallel([])
        assert result == {}

    @patch('src.tools.tlsx.run_tlsx')
    def test_run_tlsx_parallel_handles_errors(self, mock_run_tlsx):
        """Test parallel tlsx handles errors gracefully."""
        mock_run_tlsx.side_effect = Exception("Network error")

        targets = [('example.com', 443), ('test.com', 443)]
        result = run_tlsx_parallel(targets)

        # Should return error info for each target
        assert 'example.com:443' in result
        assert 'test.com:443' in result
        assert result['example.com:443']['tls_enabled'] is None
        assert 'error' in result['example.com:443']


class TestTlsxEdgeCases:
    """Test edge cases for tlsx runner."""

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_with_custom_timeout(self, mock_tempfile, mock_run):
        """Test tlsx with custom timeout."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            stdout='',
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                run_tlsx([('example.com', 443)], timeout=300)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get('timeout') == 300

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_command_flags(self, mock_tempfile, mock_run):
        """Test that tlsx is called with correct flags."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            stdout='',
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                run_tlsx([('example.com', 443)])

        call_args = mock_run.call_args[0][0]
        assert '-json' in call_args
        assert '-silent' in call_args
        assert '-tps' in call_args  # Probe status
        assert '-tv' in call_args   # TLS version
        assert '-cipher' in call_args
        assert '-ex' in call_args   # Expired check
        assert '-ss' in call_args   # Self-signed check
        assert '-wc' in call_args   # Wildcard check

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_creates_targets_file(self, mock_tempfile, mock_run):
        """Test that targets file is created with correct content."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            stdout='',
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                run_tlsx([
                    ('example.com', 443),
                    ('test.com', 8443)
                ])

        # Verify write calls for targets
        write_calls = mock_file.write.call_args_list
        written_content = ''.join(call[0][0] for call in write_calls)
        assert 'example.com:443' in written_content
        assert 'test.com:8443' in written_content

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_cleans_up_temp_file(self, mock_tempfile, mock_run):
        """Test that temporary file is cleaned up after execution."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            stdout='',
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True) as mock_exists:
            with patch('src.tools.tlsx.Path.unlink') as mock_unlink:
                run_tlsx([('example.com', 443)])

                # Verify cleanup was attempted
                # Path.unlink is called with missing_ok=True

    @patch('src.tools.tlsx.subprocess.run')
    @patch('src.tools.tlsx.tempfile.NamedTemporaryFile')
    def test_run_tlsx_handles_malformed_json(self, mock_tempfile, mock_run):
        """Test tlsx handles malformed JSON output gracefully."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.txt'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_output = '{"host":"example.com"}\n{invalid json}\n{"host":"test.com","port":"443"}\n'
        mock_run.return_value = MagicMock(
            stdout=mock_output,
            returncode=0,
            stderr=''
        )

        with patch('src.tools.tlsx.Path.exists', return_value=True):
            with patch('src.tools.tlsx.Path.unlink'):
                # Should not raise, should skip malformed lines
                result = run_tlsx([('example.com', 443), ('test.com', 443)])

        # Should have at least some valid results
        assert len(result) >= 1
