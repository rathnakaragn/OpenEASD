"""
Collection utility functions for OpenEASD.

Provides reusable functions for common collection operations
like deduplication, filtering, and transformation.
"""

from typing import List, Dict, Any, Callable, TypeVar, Set

T = TypeVar('T')


def deduplicate_by_key(
    items: List[T],
    key_func: Callable[[T], str],
    case_insensitive: bool = True
) -> List[T]:
    """
    Deduplicate a list of items by a key function.

    Args:
        items: List of items to deduplicate
        key_func: Function that extracts the key from each item
        case_insensitive: If True, keys are compared case-insensitively

    Returns:
        List of unique items (preserves original order)

    Example:
        >>> items = [{'name': 'api.example.com'}, {'name': 'API.example.com'}]
        >>> deduplicate_by_key(items, lambda x: x['name'])
        [{'name': 'api.example.com'}]
    """
    seen: Set[str] = set()
    unique: List[T] = []

    for item in items:
        key = key_func(item)
        if case_insensitive and isinstance(key, str):
            key = key.lower()

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


def deduplicate_strings(
    items: List[str],
    case_insensitive: bool = True
) -> List[str]:
    """
    Deduplicate a list of strings.

    Args:
        items: List of strings to deduplicate
        case_insensitive: If True, strings are compared case-insensitively

    Returns:
        List of unique strings (preserves original order)

    Example:
        >>> deduplicate_strings(['api.example.com', 'API.example.com', 'www.example.com'])
        ['api.example.com', 'www.example.com']
    """
    seen: Set[str] = set()
    unique: List[str] = []

    for item in items:
        key = item.lower() if case_insensitive else item

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


def group_by_key(
    items: List[Dict[str, Any]],
    key: str
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group a list of dictionaries by a key.

    Args:
        items: List of dictionaries to group
        key: Dictionary key to group by

    Returns:
        Dictionary mapping key values to lists of items

    Example:
        >>> items = [{'host': 'a', 'port': 80}, {'host': 'a', 'port': 443}]
        >>> group_by_key(items, 'host')
        {'a': [{'host': 'a', 'port': 80}, {'host': 'a', 'port': 443}]}
    """
    result: Dict[str, List[Dict[str, Any]]] = {}

    for item in items:
        key_value = str(item.get(key, ''))
        if key_value not in result:
            result[key_value] = []
        result[key_value].append(item)

    return result


__all__ = [
    'deduplicate_by_key',
    'deduplicate_strings',
    'group_by_key',
]
