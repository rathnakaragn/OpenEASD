"""
Domain management service.

Handles business logic for domain operations including
creation, updates, listing, and deletion.
"""

from typing import List, Dict, Any, Optional
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain
from src.services.exceptions import DomainNotFound, DomainAlreadyExists, InvalidDomainFormat
from src.data.models.domain import Domain


class DomainService:
    """Service for managing domains."""

    def __init__(self, db_manager: SQLModelManager):
        """
        Initialize domain service.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

    def create_domain(
        self,
        domain: str,
        is_primary: bool = False,
        contact_email: Optional[str] = None,
        scan_frequency: Optional[str] = None
    ) -> Domain:
        """
        Create a new domain.

        Args:
            domain: Domain name to add
            is_primary: Whether this is a primary domain
            contact_email: Optional contact email
            scan_frequency: Optional scan frequency (hourly, daily, weekly, monthly)

        Returns:
            The created domain object.

        Raises:
            InvalidDomainFormat: If domain format is invalid.
            DomainAlreadyExists: If domain already exists.
        """
        try:
            domain = validate_domain(domain)
        except ValueError as e:
            raise InvalidDomainFormat(str(e))

        if self.db.domain_exists(domain):
            raise DomainAlreadyExists(f'Domain {domain} already exists')

        return self.db.add_domain(
            domain=domain,
            is_primary=is_primary,
            contact_email=contact_email,
            scan_frequency=scan_frequency
        )

    def list_domains(
        self,
        limit: int = 20,
        primary_only: bool = False
    ) -> Dict[str, Any]:
        """
        List domains with optional filtering.

        Args:
            limit: Maximum number of domains to return
            primary_only: Only return primary domains

        Returns:
            Dictionary containing domains list and metadata
        """
        result = self.db.get_domains(
            limit=limit,
            primary_only=primary_only
        )

        return {
            'success': True,
            'domains': result['domains'],
            'total_count': result['total_count'],
            'has_more': result['has_more']
        }

    def get_domain(self, domain: str) -> Domain:
        """
        Get detailed information about a specific domain.

        Args:
            domain: Domain name to retrieve

        Returns:
            The domain object.

        Raises:
            DomainNotFound: If domain doesn't exist
        """
        try:
            domain = validate_domain(domain)
        except ValueError as e:
            raise InvalidDomainFormat(str(e))

        if not self.db.domain_exists(domain):
            raise DomainNotFound(f'Domain {domain} not found')

        result = self.db.get_domains(domain_name=domain, limit=1)

        if not result['domains']:
            raise DomainNotFound(f'Could not retrieve details for {domain}')

        return result['domains'][0]

    def update_domain(
        self,
        domain: str,
        is_primary: Optional[bool] = None
    ) -> Domain:
        """
        Update domain metadata.

        Args:
            domain: Domain name to update
            is_primary: New primary status

        Returns:
            The updated domain object.

        Raises:
            DomainNotFound: If domain doesn't exist or no fields to update
        """
        try:
            domain = validate_domain(domain)
        except ValueError as e:
            raise InvalidDomainFormat(str(e))

        if not self.db.domain_exists(domain):
            raise DomainNotFound(f'Domain {domain} not found')

        update_fields = {}

        if is_primary is not None:
            update_fields['is_primary'] = is_primary

        if not update_fields:
            raise ValueError('No fields provided to update. Use is_primary')

        return self.db.update_domain(domain, **update_fields)

    def delete_domain(self, domain: str) -> Dict[str, Any]:
        """
        Delete a domain and all associated data.

        Args:
            domain: Domain name to delete

        Returns:
            Dictionary containing deletion results

        Raises:
            DomainNotFound: If domain doesn't exist
        """
        try:
            domain = validate_domain(domain)
        except ValueError as e:
            raise InvalidDomainFormat(str(e))

        if not self.db.domain_exists(domain):
            raise DomainNotFound(f'Domain {domain} not found')

        deleted_counts = self.db.delete_domain_with_data(domain)

        return {
            'success': True,
            'message': f'Successfully deleted domain {domain}',
            'deleted': deleted_counts
        }
