"""
Tests for domain validation utility functions.
"""

import pytest
from src.utils.validation import is_valid_domain, validate_domain, validate_domains

def test_is_valid_domain():
    """Test the is_valid_domain function."""
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.example.co.uk") is True
    assert is_valid_domain("example-domain.com") is True
    assert is_valid_domain("123.com") is True
    assert is_valid_domain("a.com") is True
    assert is_valid_domain("example.com.") is False
    assert is_valid_domain("-example.com") is False
    assert is_valid_domain("example-.com") is False
    assert is_valid_domain("example..com") is False
    assert is_valid_domain("example@.com") is False
    assert is_valid_domain("") is False
    assert is_valid_domain(None) is False

def test_validate_domain_success():
    """Test validate_domain with a valid domain."""
    domain = "example.com"
    assert validate_domain(domain) == domain

def test_validate_domain_failure():
    """Test validate_domain with an invalid domain."""
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domain("invalid domain")

def test_validate_domains_success():
    """Test validate_domains with a list of valid domains."""
    domains = ["example.com", "sub.example.com"]
    validated = validate_domains(domains)
    assert validated == domains

def test_validate_domains_failure():
    """Test validate_domains with a list containing an invalid domain."""
    domains = ["example.com", "invalid domain"]
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domains(domains)

def test_validate_domains_empty_list():
    """Test validate_domains with an empty list."""
    assert validate_domains([]) == []

def test_validate_domains_with_none():
    """Test validate_domains with a list containing None."""
    domains = ["example.com", None]
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domains(domains)
