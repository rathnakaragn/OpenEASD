"""
Model conversion utilities for OpenEASD.

Provides generic converters for SQLModel objects to dictionaries,
eliminating repeated conversion code.

Author: Rathnakara G N
Company: Cybersecify
Created: December 2025
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type
from sqlmodel import SQLModel

from src.utils.json_utils import safe_json_load
from src.utils.timezone import to_ist

logger = logging.getLogger(__name__)


class ModelConverter:
    """
    Generic converter for SQLModel objects to dictionaries.

    Handles JSON field parsing, timezone conversion, and null value filtering.
    """

    @staticmethod
    def model_to_dict(
        model: SQLModel,
        json_fields: Optional[Set[str]] = None,
        datetime_fields: Optional[Set[str]] = None,
        exclude_none: bool = False,
        exclude_fields: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Convert SQLModel instance to dictionary.

        Args:
            model: SQLModel instance to convert
            json_fields: Field names containing JSON strings to parse
            datetime_fields: Field names containing datetime objects to convert to IST
            exclude_none: Whether to exclude None values from result
            exclude_fields: Field names to exclude from result

        Returns:
            Dictionary representation of model

        Example:
            >>> model = ScanSession(scan_id="123", domains_scanned='["a.com"]')
            >>> ModelConverter.model_to_dict(
            ...     model,
            ...     json_fields={'domains_scanned'}
            ... )
            {'scan_id': '123', 'domains_scanned': ['a.com']}
        """
        if model is None:
            return {}

        json_fields = json_fields or set()
        datetime_fields = datetime_fields or set()
        exclude_fields = exclude_fields or set()

        result = {}

        # Get all model fields (use model_fields from class for Pydantic V2 compatibility)
        model_class = type(model)
        model_fields = getattr(model_class, 'model_fields', None) or getattr(model_class, '__fields__', {})
        for field_name in model_fields:
            # Skip excluded fields
            if field_name in exclude_fields:
                continue

            value = getattr(model, field_name, None)

            # Skip None values if requested
            if exclude_none and value is None:
                continue

            # Parse JSON fields
            if field_name in json_fields and value:
                value = safe_json_load(value, default={})

            # Convert datetime to IST
            elif field_name in datetime_fields and value:
                if isinstance(value, datetime):
                    value = to_ist(value)

            result[field_name] = value

        return result

    @staticmethod
    def models_to_list(
        models: List[SQLModel],
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Convert list of SQLModel instances to list of dictionaries.

        Args:
            models: List of SQLModel instances
            **kwargs: Arguments to pass to model_to_dict()

        Returns:
            List of dictionaries

        Example:
            >>> models = [model1, model2, model3]
            >>> ModelConverter.models_to_list(
            ...     models,
            ...     json_fields={'evidence'}
            ... )
            [{'id': '1', ...}, {'id': '2', ...}, ...]
        """
        return [ModelConverter.model_to_dict(model, **kwargs) for model in models]


# ============================================================================
# Specialized Converters for Specific Models
# ============================================================================

class ScanConverter:
    """Converter for scan-related models."""

    @staticmethod
    def scan_to_dict(scan: SQLModel) -> Dict[str, Any]:
        """
        Convert ScanSession to dictionary.

        Args:
            scan: ScanSession model instance

        Returns:
            Dictionary with parsed JSON fields
        """
        return ModelConverter.model_to_dict(
            scan,
            json_fields={'domains_scanned', 'metadata'},
            datetime_fields={'started_at', 'completed_at', 'created_at'}
        )

    @staticmethod
    def subdomain_history_to_dict(history: SQLModel) -> Dict[str, Any]:
        """
        Convert SubdomainHistory to dictionary.

        Args:
            history: SubdomainHistory model instance

        Returns:
            Dictionary with parsed JSON fields
        """
        return ModelConverter.model_to_dict(
            history,
            json_fields={'meta_data'},
            datetime_fields={'first_seen', 'last_seen'}
        )


class ToolResultConverter:
    """Converter for tool result models."""

    @staticmethod
    def subfinder_result_to_dict(result: SQLModel) -> Dict[str, Any]:
        """
        Convert SubfinderResult to dictionary.

        Args:
            result: SubfinderResult model instance

        Returns:
            Dictionary representation
        """
        return ModelConverter.model_to_dict(
            result,
            datetime_fields={'discovered_at'}
        )

    @staticmethod
    def naabu_result_to_dict(result: SQLModel) -> Dict[str, Any]:
        """
        Convert NaabuResult to dictionary.

        Args:
            result: NaabuResult model instance

        Returns:
            Dictionary representation
        """
        return ModelConverter.model_to_dict(
            result,
            datetime_fields={'scanned_at'}
        )

    @staticmethod
    def amass_result_to_dict(result: SQLModel) -> Dict[str, Any]:
        """
        Convert AmassResult to dictionary.

        Args:
            result: AmassResult model instance

        Returns:
            Dictionary representation
        """
        return ModelConverter.model_to_dict(
            result,
            json_fields={'sources'},
            datetime_fields={'discovered_at'}
        )

    @staticmethod
    def nmap_result_to_dict(result: SQLModel) -> Dict[str, Any]:
        """
        Convert NmapResult to dictionary.

        Args:
            result: NmapResult model instance

        Returns:
            Dictionary with parsed JSON fields
        """
        return ModelConverter.model_to_dict(
            result,
            json_fields={'service_info', 'os_info'},
            datetime_fields={'scanned_at'}
        )


class FindingConverter:
    """Converter for finding-related models."""

    @staticmethod
    def finding_to_dict(finding: SQLModel) -> Dict[str, Any]:
        """
        Convert Finding to dictionary.

        Args:
            finding: Finding model instance

        Returns:
            Dictionary with parsed JSON fields and IST timestamps
        """
        return ModelConverter.model_to_dict(
            finding,
            json_fields={'evidence_json', 'score_breakdown_json', 'metadata_json'},
            datetime_fields={'first_seen', 'last_seen', 'resolved_at', 'updated_at', 'created_at'}
        )

    @staticmethod
    def vulnerability_to_dict(vuln: SQLModel) -> Dict[str, Any]:
        """
        Convert Vulnerability to dictionary.

        Args:
            vuln: Vulnerability model instance

        Returns:
            Dictionary representation
        """
        return ModelConverter.model_to_dict(
            vuln,
            json_fields={'cvss_vector', 'affected_versions', 'references'},
            datetime_fields={'disclosed_at', 'updated_at'}
        )


class DomainConverter:
    """Converter for domain-related models."""

    @staticmethod
    def domain_to_dict(domain: SQLModel) -> Dict[str, Any]:
        """
        Convert Domain to dictionary.

        Args:
            domain: Domain model instance

        Returns:
            Dictionary with parsed JSON fields
        """
        return ModelConverter.model_to_dict(
            domain,
            json_fields={'tags', 'metadata'},
            datetime_fields={'last_scan', 'created_at', 'updated_at'}
        )


# ============================================================================
# Batch Conversion Utilities
# ============================================================================

def convert_scan_results(
    scans: List[SQLModel],
    include_subdomains: bool = False
) -> List[Dict[str, Any]]:
    """
    Convert list of scans with optional subdomain details.

    Args:
        scans: List of ScanSession models
        include_subdomains: Whether to include subdomain details

    Returns:
        List of scan dictionaries
    """
    results = []

    for scan in scans:
        scan_dict = ScanConverter.scan_to_dict(scan)

        if include_subdomains and hasattr(scan, 'subdomains'):
            scan_dict['subdomains'] = [
                ScanConverter.subdomain_history_to_dict(sub)
                for sub in scan.subdomains
            ]

        results.append(scan_dict)

    return results


def convert_findings_with_vulnerabilities(
    findings: List[SQLModel]
) -> List[Dict[str, Any]]:
    """
    Convert findings with associated vulnerability details.

    Args:
        findings: List of Finding models with vulnerability relationships

    Returns:
        List of finding dictionaries with vulnerability data
    """
    results = []

    for finding in findings:
        finding_dict = FindingConverter.finding_to_dict(finding)

        if hasattr(finding, 'vulnerabilities') and finding.vulnerabilities:
            finding_dict['vulnerabilities'] = [
                FindingConverter.vulnerability_to_dict(vuln)
                for vuln in finding.vulnerabilities
            ]

        results.append(finding_dict)

    return results
