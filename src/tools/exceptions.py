"""
Tool layer exceptions.

These exceptions are used by all security tools (subfinder, naabu, nuclei, etc.).
Defined here to avoid circular imports between tools and services layers.
"""


class ToolExecutionError(Exception):
    """Raised when a security tool execution fails."""
    pass


class ToolTimeoutError(ToolExecutionError):
    """Raised when a security tool execution times out."""
    pass


class ToolNotFoundError(ToolExecutionError):
    """Raised when a security tool executable is not found."""
    pass


class ToolOutputParseError(ToolExecutionError):
    """Raised when tool output cannot be parsed."""
    pass
