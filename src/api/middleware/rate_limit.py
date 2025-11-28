"""
Rate limiting middleware for API endpoints.
"""

import time
import logging
from collections import defaultdict
from threading import Lock
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""

    # Class-level reference to the singleton instance
    _instance = None

    def __init__(self, app, default_limit: int = 100, window_seconds: int = 3600):
        """
        Initialize rate limiter.

        Args:
            app: FastAPI application
            default_limit: Default number of requests allowed per window
            window_seconds: Time window in seconds (default: 1 hour)
        """
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds

        # Endpoint-specific limits (requests per hour)
        self.endpoint_limits = {
            "/api/v1/scans": 10,  # Scan execution
            "/api/v1/domains": 50,  # Domain operations
        }

        # Storage for request counts: {client_id: {endpoint: [(timestamp, count)]}}
        self.request_counts = defaultdict(lambda: defaultdict(list))
        self.lock = Lock()

        # Set the singleton instance for testing
        RateLimitMiddleware._instance = self

    @classmethod
    def reset(cls):
        """Reset rate limit state for testing."""
        if cls._instance:
            cls._instance.request_counts.clear()

    async def dispatch(self, request: Request, call_next):
        """Process request and enforce rate limits."""
        # Only rate limit write operations
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return await call_next(request)

        # Skip rate limiting for health checks
        if request.url.path in {"/api/v1/health", "/health"}:
            return await call_next(request)

        # Get client identifier (API key ID or IP address)
        client_id = self._get_client_id(request)

        # Get endpoint path (strip query params)
        endpoint = self._normalize_endpoint(request.url.path)

        # Check rate limit
        if not self._check_rate_limit(client_id, endpoint):
            # Get limit info for error message
            limit, remaining = self._get_limit_info(client_id, endpoint)
            retry_after = self._get_retry_after(client_id, endpoint)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded. Maximum {limit} requests per hour for this endpoint.",
                    "retry_after": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(int(time.time()) + self.window_seconds)
                }
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        limit, remaining = self._get_limit_info(client_id, endpoint)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.window_seconds)

        return response

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier from request."""
        # Prefer API key ID if authenticated
        if hasattr(request.state, "api_key_id") and request.state.api_key_id:
            return f"key:{request.state.api_key_id}"

        # Fall back to IP address
        if request.client:
            return f"ip:{request.client.host}"

        return "unknown"

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for rate limiting."""
        # Group similar endpoints together
        # e.g., /api/v1/domains/example.com -> /api/v1/domains
        parts = path.split("/")
        if len(parts) >= 4:
            return "/".join(parts[:4])  # /api/v1/resource
        return path

    def _check_rate_limit(self, client_id: str, endpoint: str) -> bool:
        """
        Check if request is within rate limit.

        Args:
            client_id: Client identifier
            endpoint: Normalized endpoint path

        Returns:
            True if within limit, False if exceeded
        """
        with self.lock:
            current_time = time.time()
            window_start = current_time - self.window_seconds

            # Get requests for this client and endpoint
            requests = self.request_counts[client_id][endpoint]

            # Remove expired requests (outside the window)
            requests = [req for req in requests if req > window_start]
            self.request_counts[client_id][endpoint] = requests

            # Get limit for this endpoint
            limit = self.endpoint_limits.get(endpoint, self.default_limit)

            # Check if limit exceeded
            if len(requests) >= limit:
                return False

            # Add current request
            requests.append(current_time)
            return True

    def _get_limit_info(self, client_id: str, endpoint: str) -> tuple:
        """
        Get rate limit information.

        Returns:
            (limit, remaining) tuple
        """
        with self.lock:
            current_time = time.time()
            window_start = current_time - self.window_seconds

            requests = self.request_counts[client_id][endpoint]
            requests = [req for req in requests if req > window_start]

            limit = self.endpoint_limits.get(endpoint, self.default_limit)
            remaining = max(0, limit - len(requests))

            return limit, remaining

    def _get_retry_after(self, client_id: str, endpoint: str) -> int:
        """
        Get seconds until rate limit resets.

        Returns:
            Seconds until oldest request expires
        """
        with self.lock:
            current_time = time.time()
            window_start = current_time - self.window_seconds

            requests = self.request_counts[client_id][endpoint]
            requests = [req for req in requests if req > window_start]

            if not requests:
                return 0

            # Time until oldest request expires
            oldest_request = min(requests)
            return int((oldest_request + self.window_seconds) - current_time)
