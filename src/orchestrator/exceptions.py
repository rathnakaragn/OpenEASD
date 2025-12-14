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


class ScanNotFound(ServiceException):
    """Raised when a scan is not found."""
    pass


class InvalidUpdateOperation(ServiceException):
    """Raised when an update operation has no fields to update."""
    pass


class InvalidScanStatus(ServiceException):
    """Raised when scan status is not valid for the requested operation."""
    pass


class ScanCannotBeDeleted(ServiceException):
    """Raised when attempting to delete a scan that cannot be deleted."""
    pass


class FindingNotFound(ServiceException):
    """Raised when a finding is not found."""
    pass


class InvalidFindingStatus(ServiceException):
    """Raised when an invalid finding status is provided."""
    pass


class InvalidFilterValue(ServiceException):
    """Raised when an invalid filter value is provided."""
    pass


# Tool exceptions - re-exported from tools layer for backwards compatibility
from src.tools.exceptions import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
    ToolOutputParseError,
)