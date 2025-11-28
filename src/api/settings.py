"""
FastAPI application settings.

Loads configuration from the Config system and provides typed settings for the API.

Author: Rathnakara G N
Company: Cybersecify
Created: November 2025
"""

from typing import List
from src.utils.config import Config


class APISettings:
    """FastAPI application settings loaded from config."""

    def __init__(self):
        """Initialize API settings from config."""
        self.config = Config()

    @property
    def title(self) -> str:
        """Get API title."""
        return self.config.get('api.title', 'OpenEASD API (Read-Only)')

    @property
    def description(self) -> str:
        """Get API description."""
        default_desc = """
        Read-Only API for monitoring External Attack Surface Detection.

        **Security Model:**
        - API: Read-only access (GET requests only)
        - CLI: Full access for all operations (add, update, delete, scan)

        **For write operations, use the CLI:**
        - Domain management: `openeasd domain add/update/remove`
        - Scan execution: `openeasd scan domain <domain>`
        - Batch scanning: `openeasd scan`
        """
        return self.config.get('api.description', default_desc)

    @property
    def version(self) -> str:
        """Get API version."""
        return self.config.get('api.version', '2.0.0-readonly')

    @property
    def host(self) -> str:
        """Get API host."""
        return self.config.get('api.host', '0.0.0.0')

    @property
    def port(self) -> int:
        """Get API port."""
        return self.config.get('api.port', 8000)

    @property
    def docs_url(self) -> str:
        """Get API docs URL."""
        return self.config.get('api.docs_url', '/api/docs')

    @property
    def redoc_url(self) -> str:
        """Get API redoc URL."""
        return self.config.get('api.redoc_url', '/api/redoc')

    @property
    def openapi_url(self) -> str:
        """Get API OpenAPI JSON URL."""
        return self.config.get('api.openapi_url', '/api/openapi.json')

    @property
    def cors_allow_origins(self) -> List[str]:
        """Get CORS allowed origins."""
        return self.config.get('api.cors.allow_origins', ['*'])

    @property
    def cors_allow_credentials(self) -> bool:
        """Get CORS allow credentials."""
        return self.config.get('api.cors.allow_credentials', True)

    @property
    def cors_allow_methods(self) -> List[str]:
        """Get CORS allowed methods."""
        return self.config.get('api.cors.allow_methods', ['*'])

    @property
    def cors_allow_headers(self) -> List[str]:
        """Get CORS allowed headers."""
        return self.config.get('api.cors.allow_headers', ['*'])

    @property
    def frontend_dir(self) -> str:
        """Get frontend directory path."""
        return self.config.get('api.frontend_dir', 'frontend')

    @property
    def reload(self) -> bool:
        """Get auto-reload setting."""
        return self.config.get('api.reload', False)


# Global settings instance
settings = APISettings()
