"""
Input validation utilities for OpenEASD.

Provides validation functions to prevent injection attacks and ensure data integrity.
"""

import re
from typing import List


# Domain validation regex (RFC 1123)
# Allows: alphanumeric, hyphens, dots
# Domain labels: 1-63 characters
# Total length: max 253 characters
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain is valid, False otherwise

    Examples:
        >>> is_valid_domain('example.com')
        True
        >>> is_valid_domain('api.example.com')
        True
        >>> is_valid_domain('invalid..com')
        False
        >>> is_valid_domain('example.com; rm -rf /')
        False
    """
    if not domain or not isinstance(domain, str):
        return False

    # Check length
    if len(domain) > 253:
        return False

    # Check for invalid characters and patterns
    if '..' in domain:
        return False

    # Check against regex pattern
    if not DOMAIN_PATTERN.match(domain):
        return False

    # Additional security checks
    # Prevent common injection patterns
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    if any(char in domain for char in dangerous_chars):
        return False

    return True


def validate_domain(domain: str) -> str:
    """
    Validate domain name and raise exception if invalid.

    Args:
        domain: Domain name to validate

    Returns:
        The validated domain name

    Raises:
        ValueError: If domain is invalid

    Examples:
        >>> validate_domain('example.com')
        'example.com'
        >>> validate_domain('invalid domain')
        Traceback (most recent call last):
        ...
        ValueError: Invalid domain format: invalid domain
    """
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain


def validate_domains(domains: List[str]) -> List[str]:
    """
    Validate a list of domain names.

    Args:
        domains: List of domain names to validate

    Returns:
        List of validated domain names

    Raises:
        ValueError: If any domain is invalid
    """
    validated = []
    for domain in domains:
        validated.append(validate_domain(domain))
    return validated


def sanitize_domain(domain: str) -> str:
    """
    Sanitize domain name by removing dangerous characters.

    Args:
        domain: Domain name to sanitize

    Returns:
        Sanitized domain name

    Note:
        This is a fallback. Prefer validate_domain() which rejects invalid input.
    """
    if not domain:
        return ''

    # Remove whitespace
    domain = domain.strip()

    # Remove dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r', ' ']
    for char in dangerous_chars:
        domain = domain.replace(char, '')

    return domain
