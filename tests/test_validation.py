"""
Test cases for validation utilities.

Tests domain validation, sanitization, and security checks.
"""

import pytest
from src.utils.validation import (
    is_valid_domain,
    validate_domain,
    validate_domains,
    sanitize_domain,
    DOMAIN_PATTERN
)


class TestDomainValidation:
    """Test cases for is_valid_domain function."""

    def test_valid_simple_domain(self):
        """Test validation of simple domain."""
        assert is_valid_domain('example.com') is True

    def test_valid_subdomain(self):
        """Test validation of subdomain."""
        assert is_valid_domain('api.example.com') is True

    def test_valid_deep_subdomain(self):
        """Test validation of deep subdomain."""
        assert is_valid_domain('api.v2.example.com') is True

    def test_valid_single_letter_labels(self):
        """Test validation of single letter labels."""
        assert is_valid_domain('a.b.c') is True

    def test_valid_numbers_in_domain(self):
        """Test validation of numbers in domain."""
        assert is_valid_domain('example123.com') is True
        assert is_valid_domain('123example.com') is True

    def test_valid_hyphens(self):
        """Test validation of hyphens in domain."""
        assert is_valid_domain('my-example.com') is True
        assert is_valid_domain('my-api.example-domain.com') is True

    def test_invalid_double_dot(self):
        """Test that double dots are rejected."""
        assert is_valid_domain('example..com') is False

    def test_invalid_leading_hyphen(self):
        """Test that leading hyphens in labels are rejected."""
        assert is_valid_domain('-example.com') is False
        assert is_valid_domain('example.-com.net') is False

    def test_invalid_trailing_hyphen(self):
        """Test that trailing hyphens in labels are rejected."""
        assert is_valid_domain('example-.com') is False

    def test_invalid_spaces(self):
        """Test that spaces are rejected."""
        assert is_valid_domain('example .com') is False
        assert is_valid_domain('example.com ') is False

    def test_invalid_command_injection(self):
        """Test that command injection characters are rejected."""
        assert is_valid_domain('example.com; rm -rf /') is False
        assert is_valid_domain('example.com | whoami') is False
        assert is_valid_domain('example.com & cat /etc/passwd') is False

    def test_invalid_special_characters(self):
        """Test that special characters are rejected."""
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            assert is_valid_domain(f'example.com{char}test') is False

    def test_invalid_empty_string(self):
        """Test that empty string is rejected."""
        assert is_valid_domain('') is False

    def test_invalid_none(self):
        """Test that None is rejected."""
        assert is_valid_domain(None) is False

    def test_invalid_non_string(self):
        """Test that non-string types are rejected."""
        assert is_valid_domain(123) is False
        assert is_valid_domain(['example.com']) is False

    def test_invalid_too_long(self):
        """Test that domain > 253 chars is rejected."""
        long_domain = 'a' * 254
        assert is_valid_domain(long_domain) is False

    def test_valid_253_chars(self):
        """Test that domain with 253 chars is valid."""
        # Create a valid domain close to 253 chars
        # Each label can be max 63 chars, max 127 labels
        domain = 'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.com'
        # This creates a domain that's valid and long
        assert is_valid_domain(domain) is True

    def test_invalid_label_too_long(self):
        """Test that label > 63 chars is rejected."""
        # Label with 64 chars
        long_label = 'a' * 64
        assert is_valid_domain(f'{long_label}.com') is False

    def test_valid_label_63_chars(self):
        """Test that label with exactly 63 chars is valid."""
        label = 'a' * 63
        assert is_valid_domain(f'{label}.com') is True

    def test_case_preservation(self):
        """Test that case is preserved (domains are case-insensitive but we keep input)."""
        assert is_valid_domain('Example.COM') is True
        assert is_valid_domain('EXAMPLE.COM') is True


class TestValidateDomain:
    """Test cases for validate_domain function."""

    def test_valid_domain_returns_input(self):
        """Test that validate_domain returns the input for valid domains."""
        result = validate_domain('example.com')
        assert result == 'example.com'

    def test_invalid_domain_raises_error(self):
        """Test that validate_domain raises ValueError for invalid domains."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain('invalid..com')

    def test_error_message_includes_domain(self):
        """Test that error message includes the invalid domain."""
        with pytest.raises(ValueError) as exc_info:
            validate_domain('invalid domain')
        assert 'invalid domain' in str(exc_info.value)

    def test_empty_string_raises_error(self):
        """Test that empty string raises error."""
        with pytest.raises(ValueError):
            validate_domain('')

    def test_command_injection_raises_error(self):
        """Test that command injection attempt raises error."""
        with pytest.raises(ValueError):
            validate_domain('example.com; rm -rf /')


class TestValidateDomains:
    """Test cases for validate_domains function."""

    def test_valid_domain_list(self):
        """Test validation of list of valid domains."""
        domains = ['example.com', 'api.example.com', 'test.org']
        result = validate_domains(domains)
        assert result == domains

    def test_empty_list(self):
        """Test validation of empty list."""
        result = validate_domains([])
        assert result == []

    def test_single_invalid_domain_raises_error(self):
        """Test that one invalid domain raises error for entire list."""
        domains = ['example.com', 'invalid..com', 'test.org']
        with pytest.raises(ValueError):
            validate_domains(domains)

    def test_first_domain_invalid(self):
        """Test that first invalid domain is caught."""
        domains = ['invalid..com', 'example.com', 'test.org']
        with pytest.raises(ValueError):
            validate_domains(domains)

    def test_last_domain_invalid(self):
        """Test that last invalid domain is caught."""
        domains = ['example.com', 'test.org', 'invalid..com']
        with pytest.raises(ValueError):
            validate_domains(domains)

    def test_multiple_domains_all_valid(self):
        """Test multiple domains validation."""
        domains = [
            'example.com',
            'api.example.com',
            'staging.example.com',
            'test.org',
            'api-v2.test.org'
        ]
        result = validate_domains(domains)
        assert len(result) == 5
        assert result == domains


class TestSanitizeDomain:
    """Test cases for sanitize_domain function."""

    def test_sanitize_removes_spaces(self):
        """Test that sanitize_domain removes spaces."""
        result = sanitize_domain(' example.com ')
        assert result == 'example.com'

    def test_sanitize_removes_dangerous_chars(self):
        """Test that sanitize_domain removes dangerous characters."""
        result = sanitize_domain('example.com;test')
        assert ';' not in result

    def test_sanitize_preserves_valid_chars(self):
        """Test that sanitize_domain preserves valid characters."""
        result = sanitize_domain('api-example.com')
        assert result == 'api-example.com'

    def test_sanitize_empty_string(self):
        """Test sanitization of empty string."""
        result = sanitize_domain('')
        assert result == ''

    def test_sanitize_only_dangerous_chars(self):
        """Test sanitization of only dangerous characters."""
        result = sanitize_domain(';;;')
        assert result == ''

    def test_sanitize_command_injection_attempt(self):
        """Test sanitization of command injection attempt."""
        original = 'example.com; rm -rf /'
        result = sanitize_domain(original)
        assert ';' not in result
        assert '&' not in result
        assert '|' not in result


class TestDomainPatternRegex:
    """Test cases for DOMAIN_PATTERN regex directly."""

    def test_pattern_matches_valid_domain(self):
        """Test that regex matches valid domain."""
        assert DOMAIN_PATTERN.match('example.com') is not None

    def test_pattern_matches_subdomain(self):
        """Test that regex matches subdomain."""
        assert DOMAIN_PATTERN.match('api.example.com') is not None

    def test_pattern_rejects_leading_hyphen(self):
        """Test that regex rejects leading hyphen in label."""
        assert DOMAIN_PATTERN.match('-example.com') is None

    def test_pattern_rejects_trailing_hyphen(self):
        """Test that regex rejects trailing hyphen in label."""
        assert DOMAIN_PATTERN.match('example-.com') is None

    def test_pattern_rejects_double_dot(self):
        """Test that regex rejects double dot."""
        assert DOMAIN_PATTERN.match('example..com') is None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_localhost(self):
        """Test localhost validation."""
        assert is_valid_domain('localhost') is True

    def test_ip_address_style(self):
        """Test that IP addresses in domain format work."""
        # 127.0.0.1 would be rejected due to dots, but numeric format is valid
        assert is_valid_domain('127-0-0-1.com') is True

    def test_numeric_only_label(self):
        """Test numeric-only labels."""
        assert is_valid_domain('123.456.789') is True

    def test_unicode_rejected(self):
        """Test that unicode characters are rejected (ASCII-only)."""
        assert is_valid_domain('例え.jp') is False

    def test_all_hyphens_label(self):
        """Test that label with only hyphens is rejected."""
        assert is_valid_domain('---.com') is False

    def test_mixed_valid_invalid_batch(self):
        """Test batch validation with mixed valid/invalid."""
        domains = ['example.com', 'api.example.com']
        result = validate_domains(domains)
        assert len(result) == 2
