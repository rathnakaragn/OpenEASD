"""
Domain management service.

Handles business logic for domain operations including
creation, updates, listing, and deletion.
"""

from typing import List, Dict, Any, Optional
from src.data.database.sqlmodel_manager import SQLModelManager
from src.utils.validation import validate_domain


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
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None,
        contact_email: Optional[str] = None,
        scan_frequency: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new domain.

        Args:
            domain: Domain name to add
            is_primary: Whether this is a primary domain
            notes: Optional notes about the domain
            tags: Optional list of tags
            contact_email: Optional contact email
            scan_frequency: Optional scan frequency (hourly, daily, weekly, monthly)

        Returns:
            Dictionary containing success status and domain data

        Raises:
            ValueError: If domain format is invalid or domain already exists
        """
        # Validate domain format
        domain = validate_domain(domain)

        # Check if domain already exists
        if self.db.domain_exists(domain):
            raise ValueError(f'Domain {domain} already exists')

        # Add domain to database
        self.db.add_domain(
            domain=domain,
            is_primary=is_primary,
            notes=notes,
            tags=tags,
            contact_email=contact_email,
            scan_frequency=scan_frequency
        )

        # Get the created domain
        result = self.db.get_domains(domain_name=domain, limit=1)

        return {
            'success': True,
            'domain': result['domains'][0] if result['domains'] else None
        }

    def list_domains(
        self,
        limit: int = 20,
        domain_type: Optional[str] = None,
        primary_only: bool = False
    ) -> Dict[str, Any]:
        """
        List domains with optional filtering.

        Args:
            limit: Maximum number of domains to return
            domain_type: Filter by domain type ('apex' or 'subdomain')
            primary_only: Only return primary domains

        Returns:
            Dictionary containing domains list and metadata
        """
        result = self.db.get_domains(
            limit=limit,
            domain_type=domain_type,
            primary_only=primary_only
        )

        return {
            'success': True,
            'domains': result['domains'],
            'total_count': result['total_count'],
            'has_more': result['has_more']
        }

    def get_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific domain.

        Args:
            domain: Domain name to retrieve

        Returns:
            Dictionary containing domain details

        Raises:
            ValueError: If domain doesn't exist
        """
        # Validate domain format
        domain = validate_domain(domain)

        # Check if domain exists
        if not self.db.domain_exists(domain):
            raise ValueError(f'Domain {domain} not found')

        # Get domain details
        result = self.db.get_domains(domain_name=domain, limit=1)

        if not result['domains']:
            raise ValueError(f'Could not retrieve details for {domain}')

        domain_info = result['domains'][0]

        # Get subdomain history
        history = self.db.get_subdomain_history(domain, limit=10)

        return {
            'success': True,
            'domain': domain_info,
            'subdomain_count': history['total_count'],
            'recent_subdomains': history['history'][:5]
        }

    def update_domain(
        self,
        domain: str,
        is_primary: Optional[bool] = None,
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Update domain metadata.

        Args:
            domain: Domain name to update
            is_primary: New primary status
            notes: New notes
            tags: New tags list

        Returns:
            Dictionary containing success status

        Raises:
            ValueError: If domain doesn't exist or no fields to update
        """
        # Validate domain format
        domain = validate_domain(domain)

        # Check if domain exists
        if not self.db.domain_exists(domain):
            raise ValueError(f'Domain {domain} not found')

        # Build update kwargs
        update_fields = {}

        if is_primary is not None:
            update_fields['is_primary'] = is_primary

        if notes is not None:
            update_fields['notes'] = notes

        if tags is not None:
            update_fields['tags'] = tags

        if not update_fields:
            raise ValueError('No fields provided to update. Use is_primary, notes, or tags')

        # Update domain
        result = self.db.update_domain(domain, **update_fields)

        return {
            'success': True,
            'updated': result
        }

    def delete_domain(self, domain: str, force: bool = False) -> Dict[str, Any]:
        """
        Delete a domain and all associated data.

        Args:
            domain: Domain name to delete
            force: Skip confirmation (for API use)

        Returns:
            Dictionary containing deletion results

        Raises:
            ValueError: If domain doesn't exist
        """
        # Validate domain format
        domain = validate_domain(domain)

        # Check if domain exists
        if not self.db.domain_exists(domain):
            raise ValueError(f'Domain {domain} not found')

        # Get totals for reporting (if not force)
        totals = None
        if not force:
            totals = self.db.get_domain_data_totals(domain)

        # Delete domain and all associated data
        deleted = self.db.delete_domain_with_data(domain)

        return {
            'success': True,
            'deleted': deleted,
            'totals': totals
        }
