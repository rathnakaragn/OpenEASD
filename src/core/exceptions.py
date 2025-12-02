"""
Custom exception types for OpenEASD.

Provides specific exception classes with context for better error handling.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

from typing import Optional


# ============================================================================
# Base Exception Classes
# ============================================================================

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


# ============================================================================
# Tool Execution Exceptions
# ============================================================================

class ToolExecutionError(OpenEASDException):
    """Base exception for tool execution errors."""
    pass


class ToolTimeoutError(ToolExecutionError):
    """Tool execution exceeded timeout."""

    def __init__(self, tool_name: str, timeout: int, domain: Optional[str] = None):
        """
        Initialize timeout error.

        Args:
            tool_name: Name of the tool that timed out
            timeout: Timeout value in seconds
            domain: Target domain (if applicable)
        """
        context = {'tool': tool_name, 'timeout_seconds': timeout}
        if domain:
            context['domain'] = domain

        message = f"{tool_name} exceeded {timeout}s timeout"
        super().__init__(message, context)


class ToolNotFoundError(ToolExecutionError):
    """Required tool not found in system."""

    def __init__(self, tool_name: str, install_hint: Optional[str] = None):
        """
        Initialize tool not found error.

        Args:
            tool_name: Name of the missing tool
            install_hint: Installation instructions (optional)
        """
        message = f"{tool_name} not found in system PATH"
        if install_hint:
            message += f"\n\nInstall with: {install_hint}"

        super().__init__(message, {'tool': tool_name})


class ToolOutputParseError(ToolExecutionError):
    """Failed to parse tool output."""

    def __init__(self, tool_name: str, reason: str):
        """
        Initialize parse error.

        Args:
            tool_name: Name of the tool
            reason: Reason for parse failure
        """
        message = f"Failed to parse {tool_name} output: {reason}"
        super().__init__(message, {'tool': tool_name, 'reason': reason})


# ============================================================================
# Database Exceptions
# ============================================================================

class DatabaseError(OpenEASDException):
    """Base exception for database errors."""
    pass


class RecordNotFoundError(DatabaseError):
    """Requested database record not found."""

    def __init__(self, model_name: str, identifier: str, field: str = "id"):
        """
        Initialize record not found error.

        Args:
            model_name: Name of the model/table
            identifier: Value that was searched for
            field: Field name that was searched
        """
        message = f"{model_name} not found: {field}={identifier}"
        super().__init__(message, {
            'model': model_name,
            'identifier': identifier,
            'field': field
        })


class DuplicateRecordError(DatabaseError):
    """Attempted to create duplicate record."""

    def __init__(self, model_name: str, field: str, value: str):
        """
        Initialize duplicate record error.

        Args:
            model_name: Name of the model/table
            field: Field with duplicate value
            value: Duplicate value
        """
        message = f"{model_name} already exists: {field}={value}"
        super().__init__(message, {
            'model': model_name,
            'field': field,
            'value': value
        })


class InvalidQueryError(DatabaseError):
    """Invalid database query parameters."""

    def __init__(self, reason: str, params: Optional[dict] = None):
        """
        Initialize invalid query error.

        Args:
            reason: Why the query is invalid
            params: Query parameters that caused the error
        """
        message = f"Invalid query: {reason}"
        context = {'reason': reason}
        if params:
            context['params'] = params
        super().__init__(message, context)


# ============================================================================
# Validation Exceptions
# ============================================================================

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


class InvalidPortError(ValidationError):
    """Invalid port number."""

    def __init__(self, port: int, reason: Optional[str] = None):
        """
        Initialize invalid port error.

        Args:
            port: Invalid port number
            reason: Specific reason for invalidity
        """
        message = f"Invalid port number: {port}"
        if reason:
            message += f" - {reason}"
        else:
            message += " - Port must be between 1 and 65535"

        super().__init__(message, {'port': port})


class MissingRequiredFieldError(ValidationError):
    """Required field is missing."""

    def __init__(self, field_name: str, context_name: Optional[str] = None):
        """
        Initialize missing field error.

        Args:
            field_name: Name of the missing field
            context_name: Context where field is required (e.g., "scan data")
        """
        message = f"Required field missing: {field_name}"
        if context_name:
            message = f"Required field '{field_name}' missing in {context_name}"

        super().__init__(message, {'field': field_name})


class InvalidUpdateOperationError(ValidationError):
    """Invalid update operation - no fields provided."""

    def __init__(self, resource_type: str, available_fields: Optional[list] = None):
        """
        Initialize invalid update operation error.

        Args:
            resource_type: Type of resource being updated (e.g., "domain")
            available_fields: List of valid field names that can be updated
        """
        message = f"No fields provided to update {resource_type}"
        if available_fields:
            fields_str = ", ".join(available_fields)
            message += f"\n\nAvailable fields: {fields_str}"

        super().__init__(message, {
            'resource_type': resource_type,
            'available_fields': available_fields or []
        })


# ============================================================================
# Configuration Exceptions
# ============================================================================

class ConfigurationError(OpenEASDException):
    """Base exception for configuration errors."""
    pass


class MissingConfigError(ConfigurationError):
    """Required configuration is missing."""

    def __init__(self, config_key: str, config_file: Optional[str] = None):
        """
        Initialize missing config error.

        Args:
            config_key: Missing configuration key
            config_file: Configuration file path (if applicable)
        """
        message = f"Missing required configuration: {config_key}"
        context = {'config_key': config_key}

        if config_file:
            message += f" in {config_file}"
            context['config_file'] = config_file

        super().__init__(message, context)


class InvalidConfigError(ConfigurationError):
    """Configuration value is invalid."""

    def __init__(self, config_key: str, value: str, reason: str):
        """
        Initialize invalid config error.

        Args:
            config_key: Configuration key
            value: Invalid value
            reason: Why the value is invalid
        """
        message = f"Invalid configuration '{config_key}' = '{value}': {reason}"
        super().__init__(message, {
            'config_key': config_key,
            'value': value,
            'reason': reason
        })


# ============================================================================
# Analysis Exceptions
# ============================================================================

class AnalysisError(OpenEASDException):
    """Base exception for analysis errors."""
    pass


class DetectorError(AnalysisError):
    """Error in detector execution."""

    def __init__(self, detector_name: str, reason: str):
        """
        Initialize detector error.

        Args:
            detector_name: Name of the detector that failed
            reason: Failure reason
        """
        message = f"Detector '{detector_name}' failed: {reason}"
        super().__init__(message, {
            'detector': detector_name,
            'reason': reason
        })


class ScoringError(AnalysisError):
    """Error in risk scoring."""

    def __init__(self, finding_type: str, reason: str):
        """
        Initialize scoring error.

        Args:
            finding_type: Type of finding being scored
            reason: Scoring failure reason
        """
        message = f"Failed to score finding '{finding_type}': {reason}"
        super().__init__(message, {
            'finding_type': finding_type,
            'reason': reason
        })


# ============================================================================
# Scan Exceptions
# ============================================================================

class ScanError(OpenEASDException):
    """Base exception for scan-related errors."""
    pass


class ScanNotFound(ScanError):
    """Requested scan not found."""

    def __init__(self, scan_id: str):
        """
        Initialize scan not found error.

        Args:
            scan_id: Scan identifier that was not found
        """
        message = f"Scan not found: {scan_id}"
        super().__init__(message, {'scan_id': scan_id})


class InvalidScanStatusError(ScanError):
    """Scan status is not valid for requested operation."""

    def __init__(self, scan_id: str, current_status: str, required_status: str, operation: Optional[str] = None):
        """
        Initialize invalid scan status error.

        Args:
            scan_id: Scan identifier
            current_status: Current status of the scan
            required_status: Required status for the operation
            operation: Operation that was attempted (e.g., "analysis")
        """
        message = f"Scan {scan_id} cannot be processed"
        if operation:
            message = f"Cannot run {operation} on scan {scan_id}"

        message += f"\n\nCurrent status: {current_status}"
        message += f"\nRequired status: {required_status}"

        super().__init__(message, {
            'scan_id': scan_id,
            'current_status': current_status,
            'required_status': required_status,
            'operation': operation
        })
