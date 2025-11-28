"""
Audit logging middleware for tracking API write operations.
"""

import json
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from src.data.database.sqlmodel_manager import SQLModelManager

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware to log all write operations to audit log."""

    # Write operations that should be logged
    WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    # Mapping of endpoints to resource types
    RESOURCE_TYPE_MAP = {
        "/api/v1/domains": "domain",
        "/api/v1/scans": "scan",
        "/api/v1/analysis": "analysis"
    }

    # Mapping of methods to actions
    ACTION_MAP = {
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete"
    }

    async def dispatch(self, request: Request, call_next):
        """Process request and log write operations."""
        # Get response
        response = await call_next(request)

        # Only log write operations
        if request.method not in self.WRITE_METHODS:
            return response

        # Only log API endpoints (skip /docs, /health, etc.)
        if not request.url.path.startswith("/api/v1/"):
            return response

        # Extract audit information
        try:
            # Get API key ID from request state (set by verify_api_key dependency)
            api_key_id = getattr(request.state, "api_key_id", None)

            # Determine resource type
            resource_type = self._get_resource_type(request.url.path)

            # Determine action
            action = self.ACTION_MAP.get(request.method, "unknown")

            # Special handling for scan execution
            if "/scans" in request.url.path and request.method == "POST":
                action = "execute"

            # Get resource ID from path if available
            resource_id = self._extract_resource_id(request.url.path)

            # Get request body (for audit trail)
            request_body = None
            if hasattr(request, "_body"):
                try:
                    request_body = request._body.decode('utf-8')
                except (AttributeError, UnicodeDecodeError):
                    pass

            # Determine success based on status code
            success = 200 <= response.status_code < 400

            # Log to database
            db = SQLModelManager()
            try:
                db.initialize()
                db.create_audit_log(
                    endpoint=request.url.path,
                    method=request.method,
                    resource_type=resource_type,
                    action=action,
                    ip_address=request.client.host if request.client else "unknown",
                    response_status=response.status_code,
                    success=success,
                    api_key_id=api_key_id,
                    resource_id=resource_id,
                    user_agent=request.headers.get("user-agent"),
                    request_body=request_body
                )
            except Exception as e:
                logger.error(f"Failed to create audit log: {e}", exc_info=True)
            finally:
                db.close()

        except Exception as e:
            # Don't fail the request if audit logging fails
            logger.error(f"Audit logging error: {e}", exc_info=True)

        return response

    def _get_resource_type(self, path: str) -> str:
        """Extract resource type from path."""
        for endpoint, resource_type in self.RESOURCE_TYPE_MAP.items():
            if endpoint in path:
                return resource_type
        return "unknown"

    def _extract_resource_id(self, path: str) -> str:
        """Extract resource ID from path."""
        # Pattern: /api/v1/domains/{domain} or /api/v1/scans/{scan_id}
        parts = path.split("/")
        if len(parts) >= 5:  # /api/v1/resource/{id}
            return parts[4]
        return None
