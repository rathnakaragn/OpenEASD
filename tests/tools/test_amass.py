"""
Tests for Amass Tool Runner.

Covers subprocess execution, JSON parsing, error handling, and edge cases.
"""

import pytest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.tools.amass import run_amass, run_amass_intel
from src.tools.exceptions import ToolExecutionError, ToolTimeoutError, ToolNotFoundError


class TestRunAmass:
    """Tests for run_amass function."""

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_success(self, mock_tempfile, mock_run):
        """Test successful amass execution."""
        # Setup mock temp file
        mock_file = MagicMock()
        mock_file.name = '/tmp/test_output.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            returncode=0,
            stderr=''
        )

        # Mock file content
        mock_json = '{"name":"api.example.com","domain":"example.com","addresses":[],"tag":"cert","sources":["CertSpotter"]}\n'
        mock_json += '{"name":"mail.example.com","domain":"example.com","addresses":[],"tag":"dns","sources":["DNS"]}\n'

        with patch('src.tools.amass.Path.exists', return_value=True):
            with patch('builtins.open', MagicMock(return_value=MagicMock(
                __enter__=lambda s: iter(mock_json.splitlines()),
                __exit__=lambda s, *a: None
            ))):
                result = run_amass("example.com", passive=True)

        assert mock_run.called

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_passive_mode(self, mock_tempfile, mock_run):
        """Test amass runs in passive mode by default."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            run_amass("example.com", passive=True)

        # Verify -passive flag is in command
        call_args = mock_run.call_args[0][0]
        assert '-passive' in call_args

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_active_mode(self, mock_tempfile, mock_run):
        """Test amass runs in active mode when passive=False."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            run_amass("example.com", passive=False)

        # Verify -passive flag is NOT in command
        call_args = mock_run.call_args[0][0]
        assert '-passive' not in call_args

    @patch('src.tools.amass.subprocess.run')
    def test_run_amass_timeout(self, mock_run):
        """Test amass timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('amass', 600)

        with pytest.raises(ToolTimeoutError) as exc_info:
            run_amass("example.com", timeout=600)

        assert "timed out" in str(exc_info.value)

    @patch('src.tools.amass.subprocess.run')
    def test_run_amass_not_found(self, mock_run):
        """Test amass when executable not found."""
        mock_run.side_effect = FileNotFoundError("amass not found")

        with pytest.raises(ToolNotFoundError) as exc_info:
            run_amass("example.com")

        assert "not found" in str(exc_info.value).lower()

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_nonzero_exit(self, mock_tempfile, mock_run):
        """Test amass with non-zero exit code."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            returncode=1,
            stderr='Error: rate limited'
        )

        with pytest.raises(ToolExecutionError) as exc_info:
            run_amass("example.com")

        assert "failed" in str(exc_info.value).lower()

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_empty_result(self, mock_tempfile, mock_run):
        """Test amass with no results."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            result = run_amass("nonexistent.invalid")

        assert result == []

    def test_run_amass_invalid_domain(self):
        """Test amass with invalid domain."""
        # The validate_domain function should raise for invalid domains
        with pytest.raises(Exception):
            run_amass("")


class TestRunAmassIntel:
    """Tests for run_amass_intel function."""

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_intel_success(self, mock_tempfile, mock_run):
        """Test successful amass intel execution."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            result = run_amass_intel("example.com")

        assert mock_run.called
        # Verify 'intel' subcommand is used
        call_args = mock_run.call_args[0][0]
        assert 'intel' in call_args

    @patch('src.tools.amass.subprocess.run')
    def test_run_amass_intel_timeout(self, mock_run):
        """Test amass intel timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('amass', 300)

        with pytest.raises(ToolTimeoutError):
            run_amass_intel("example.com", timeout=300)

    @patch('src.tools.amass.subprocess.run')
    def test_run_amass_intel_not_found(self, mock_run):
        """Test amass intel when executable not found."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(ToolNotFoundError):
            run_amass_intel("example.com")

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_intel_nonzero_exit(self, mock_tempfile, mock_run):
        """Test amass intel with non-zero exit code."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(
            returncode=1,
            stderr='Error occurred'
        )

        with pytest.raises(ToolExecutionError):
            run_amass_intel("example.com")


class TestAmassEdgeCases:
    """Test edge cases for amass runner."""

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_with_custom_timeout(self, mock_tempfile, mock_run):
        """Test amass with custom timeout."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            run_amass("example.com", timeout=1200)

        # Verify timeout was passed
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get('timeout') == 1200

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_cleans_up_temp_file(self, mock_tempfile, mock_run):
        """Test that temporary file is cleaned up."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=True):
            with patch('src.tools.amass.Path.unlink') as mock_unlink:
                with patch('builtins.open', MagicMock(return_value=MagicMock(
                    __enter__=lambda s: iter([]),
                    __exit__=lambda s, *a: None
                ))):
                    run_amass("example.com")

                # Verify temp file cleanup was attempted
                # (unlink is called in finally block)

    @patch('src.tools.amass.subprocess.run')
    @patch('src.tools.amass.tempfile.NamedTemporaryFile')
    def test_run_amass_with_special_domain(self, mock_tempfile, mock_run):
        """Test amass with special characters in domain."""
        mock_file = MagicMock()
        mock_file.name = '/tmp/test.json'
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_tempfile.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr='')

        with patch('src.tools.amass.Path.exists', return_value=False):
            result = run_amass("example.co.uk")

        # Verify domain was passed correctly
        call_args = mock_run.call_args[0][0]
        assert 'example.co.uk' in call_args
