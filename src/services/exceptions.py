"""
Custom exceptions for the service layer.
"""

class ServiceException(Exception):
    """Base class for service layer exceptions."""
    pass

class DomainNotFound(ServiceException):
    """Raised when a domain is not found."""
    pass

class DomainAlreadyExists(ServiceException):
    """Raised when a domain already exists."""
    pass

class InvalidDomainFormat(ServiceException):
    """Raised when a domain format is invalid."""
    pass

class CliCommandError(Exception):
    """Base class for CLI command exceptions."""
    pass