"""
Custom exception types for OpenEASD.

Provides specific exception classes with context for better error handling.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import Optional


class OpenEASDException(Exception):
    """Base exception for all OpenEASD errors."""

    def __init__(self, message: str, context: Optional[dict] = None):
        """
        Initialize exception with message and optional context.

        Args:
            message: Error message
            context: Additional context dict (e.g., {'domain': 'example.com'})
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        """String representation with context."""
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} ({context_str})"
        return self.message


class ValidationError(OpenEASDException):
    """Base exception for validation errors."""
    pass


class InvalidDomainError(ValidationError):
    """Invalid domain format."""

    def __init__(self, domain: str, reason: Optional[str] = None):
        """
        Initialize invalid domain error.

        Args:
            domain: Invalid domain string
            reason: Specific reason for invalidity
        """
        message = f"Invalid domain format: {domain}"
        if reason:
            message += f" - {reason}"

        message += "\n\nDomain must:"
        message += "\n- Contain only alphanumeric characters, hyphens, and dots"
        message += "\n- Not start or end with hyphens"
        message += "\n- Have valid TLD (e.g., .com, .org)"
        message += "\n\nExamples: example.com, api.example.com"

        super().__init__(message, {'domain': domain})
