"""
JSON utility functions for OpenEASD.

Provides safe JSON parsing and handling with proper error management.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

import json
import logging
from typing import Any, Dict, List, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar('T')


def safe_json_load(
    json_str: Optional[str],
    default: T = None,
    log_errors: bool = False
) -> Union[T, Dict, List]:
    """
    Safely parse JSON string with default fallback.

    Args:
        json_str: JSON string to parse (can be None)
        default: Default value to return on error
        log_errors: Whether to log parsing errors

    Returns:
        Parsed JSON object or default value

    Examples:
        >>> safe_json_load('{"key": "value"}')
        {'key': 'value'}
        >>> safe_json_load('invalid json', default={})
        {}
        >>> safe_json_load(None, default=[])
        []
    """
    if not json_str:
        return default

    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError) as e:
        if log_errors:
            logger.warning(f"Failed to parse JSON: {e}")
        return default


def safe_json_dump(
    obj: Any,
    default_str: str = "{}",
    log_errors: bool = False,
    **kwargs
) -> str:
    """
    Safely convert object to JSON string.

    Args:
        obj: Object to convert to JSON
        default_str: Default string to return on error
        log_errors: Whether to log conversion errors
        **kwargs: Additional arguments for json.dumps()

    Returns:
        JSON string or default string

    Examples:
        >>> safe_json_dump({'key': 'value'})
        '{"key": "value"}'
        >>> safe_json_dump(object(), default_str='null')
        'null'
    """
    try:
        return json.dumps(obj, **kwargs)
    except (TypeError, ValueError) as e:
        if log_errors:
            logger.warning(f"Failed to convert to JSON: {e}")
        return default_str


def merge_json_fields(
    json_str1: Optional[str],
    json_str2: Optional[str],
    log_errors: bool = False
) -> str:
    """
    Merge two JSON strings (dicts only).

    Later values override earlier ones. Returns empty dict JSON if both invalid.

    Args:
        json_str1: First JSON string
        json_str2: Second JSON string
        log_errors: Whether to log parsing errors

    Returns:
        Merged JSON string

    Examples:
        >>> merge_json_fields('{"a": 1}', '{"b": 2}')
        '{"a": 1, "b": 2}'
        >>> merge_json_fields('{"a": 1}', '{"a": 2}')
        '{"a": 2}'
    """
    dict1 = safe_json_load(json_str1, default={}, log_errors=log_errors)
    dict2 = safe_json_load(json_str2, default={}, log_errors=log_errors)

    if isinstance(dict1, dict) and isinstance(dict2, dict):
        merged = {**dict1, **dict2}
        return safe_json_dump(merged, log_errors=log_errors)

    if log_errors:
        logger.warning("Cannot merge non-dict JSON values")

    return safe_json_dump({}, log_errors=log_errors)


def extract_json_field(
    json_str: Optional[str],
    field_name: str,
    default: T = None,
    log_errors: bool = False
) -> Union[T, Any]:
    """
    Extract a specific field from JSON string.

    Args:
        json_str: JSON string to parse
        field_name: Field name to extract
        default: Default value if field not found
        log_errors: Whether to log errors

    Returns:
        Field value or default

    Examples:
        >>> extract_json_field('{"name": "test"}', 'name')
        'test'
        >>> extract_json_field('{"name": "test"}', 'missing', default='N/A')
        'N/A'
    """
    data = safe_json_load(json_str, default={}, log_errors=log_errors)

    if isinstance(data, dict):
        return data.get(field_name, default)

    return default


def validate_json_structure(
    json_str: Optional[str],
    required_fields: List[str],
    log_errors: bool = True
) -> bool:
    """
    Validate that JSON string contains required fields.

    Args:
        json_str: JSON string to validate
        required_fields: List of required field names
        log_errors: Whether to log validation errors

    Returns:
        True if valid, False otherwise

    Examples:
        >>> validate_json_structure('{"a": 1, "b": 2}', ['a', 'b'])
        True
        >>> validate_json_structure('{"a": 1}', ['a', 'b'])
        False
    """
    data = safe_json_load(json_str, default={}, log_errors=log_errors)

    if not isinstance(data, dict):
        if log_errors:
            logger.warning("JSON data is not a dictionary")
        return False

    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        if log_errors:
            logger.warning(f"Missing required JSON fields: {missing_fields}")
        return False

    return True
