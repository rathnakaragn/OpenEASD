"""
Dependency injection for FastAPI routes.

Provides reusable dependencies for database connections,
services, and authentication.
"""

import hashlib
import secrets
import time
from typing import Generator, Optional, Dict
from collections import defaultdict
from fastapi import Depends, HTTPException, Header, Request
from src.data.database.sqlmodel_manager import SQLModelManager
from src.services.domain_service import DomainService
from src.services.scan_service import ScanService
from src.services.alert_service import AlertService
from src.services.findings_service import FindingsService
import os


class AuthRateLimiter:
    """Simple in-memory rate limiter for failed authentication attempts."""

    def __init__(self, max_failures: int = 5, lockout_duration: int = 300):
        """
        Initialize rate limiter.

        Args:
            max_failures: Maximum failed attempts before lockout
            lockout_duration: Seconds to lock out after max failures
        """
        self.max_failures = max_failures
        self.lockout_duration = lockout_duration
        self.failed_attempts: Dict[str, list] = defaultdict(list)

    def record_failure(self, identifier: str):
        """Record a failed authentication attempt."""
        now = time.time()
        self.failed_attempts[identifier].append(now)

        # Clean old entries (older than lockout_duration)
        cutoff = now - self.lockout_duration
        self.failed_attempts[identifier] = [
            ts for ts in self.failed_attempts[identifier] if ts > cutoff
        ]

    def is_locked_out(self, identifier: str) -> bool:
        """Check if an identifier is currently locked out."""
        now = time.time()
        cutoff = now - self.lockout_duration

        # Clean old entries
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                ts for ts in self.failed_attempts[identifier] if ts > cutoff
            ]

            # Check if locked out
            return len(self.failed_attempts[identifier]) >= self.max_failures

        return False

    def get_remaining_lockout(self, identifier: str) -> int:
        """Get remaining lockout time in seconds."""
        if not self.is_locked_out(identifier):
            return 0

        if identifier not in self.failed_attempts or not self.failed_attempts[identifier]:
            return 0

        oldest_attempt = min(self.failed_attempts[identifier])
        remaining = int(self.lockout_duration - (time.time() - oldest_attempt))
        return max(0, remaining)


# Global rate limiter instance
_auth_limiter = AuthRateLimiter(max_failures=5, lockout_duration=300)


def get_db_manager() -> Generator[SQLModelManager, None, None]:
    """
    Dependency to get database manager instance.

    Yields:
        SQLModelManager instance

    Note:
        Automatically handles initialization and cleanup.
    """
    db = SQLModelManager()
    try:
        db.initialize()
        yield db
    finally:
        db.close()


def get_domain_service(db: SQLModelManager = Depends(get_db_manager)) -> DomainService:
    """
    Dependency to get domain service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        DomainService instance
    """
    return DomainService(db)


def get_scan_service(db: SQLModelManager = Depends(get_db_manager)) -> ScanService:
    """
    Dependency to get scan service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        ScanService instance
    """
    return ScanService(db)


def get_alert_service(db: SQLModelManager = Depends(get_db_manager)) -> AlertService:
    """
    Dependency to get alert service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        AlertService instance
    """
    return AlertService(db)


def get_findings_service(db: SQLModelManager = Depends(get_db_manager)) -> FindingsService:
    """
    Dependency to get findings service instance.

    Args:
        db: Database manager (injected by FastAPI)

    Returns:
        FindingsService instance
    """
    return FindingsService(db)


def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: SQLModelManager = Depends(get_db_manager),
    request: Request = None
) -> dict:
    """
    Dependency to verify API key authentication with rate limiting.

    Args:
        x_api_key: API key from X-API-Key header
        db: Database manager (injected by FastAPI)
        request: HTTP request (for IP-based rate limiting)

    Returns:
        API key information dict

    Raises:
        HTTPException: If API key is invalid, missing, or rate limited
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Use request IP for rate limiting (or default identifier)
    client_ip = "unknown"
    if request:
        client_ip = request.client.host if request.client else "unknown"

    # If in testing environment, bypass rate limiting
    if os.environ.get("OPENEASD_TESTING") == "1":
        # In a testing environment, we might want to bypass rate limiting
        # to ensure tests run without interference.
        # Still perform API key validation, just skip rate limit checks.
        pass
    else:
        # Check if client is rate limited
        if _auth_limiter.is_locked_out(client_ip):
            remaining = _auth_limiter.get_remaining_lockout(client_ip)
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed authentication attempts. Try again in {remaining} seconds.",
                headers={"Retry-After": str(remaining)}
            )

    # Hash the provided key using constant-time operation
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    # Verify against database (include inactive to check for revoked keys)
    api_key_info = db.get_api_key_by_hash(key_hash, include_inactive=True)

    # Constant-time comparison to prevent timing attacks
    # Always perform the same operations regardless of whether key exists
    auth_failed = False

    if api_key_info:
        stored_hash = api_key_info.get('key', '')
        # Use constant-time comparison
        if not secrets.compare_digest(key_hash, stored_hash):
            auth_failed = True
    else:
        # Key not found - generate a dummy hash comparison to maintain constant time
        # This prevents attackers from determining if a key exists
        dummy_hash = hashlib.sha256(b'dummy').hexdigest()
        secrets.compare_digest(key_hash, dummy_hash)
        auth_failed = True

    if auth_failed:
        # Record failure only if not in testing mode
        if os.environ.get("OPENEASD_TESTING") != "1":
            _auth_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Check if key is active
    if not api_key_info.get('is_active', False):
        _auth_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",  # Don't reveal if key was revoked vs invalid
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Check expiration if set
    if api_key_info.get('expires_at'):
        from datetime import datetime
        if datetime.utcnow() > api_key_info['expires_at']:
            _auth_limiter.record_failure(client_ip)
            raise HTTPException(
                status_code=401,
                detail="Invalid API key",  # Don't reveal if key expired vs invalid
                headers={"WWW-Authenticate": "ApiKey"}
            )

    return api_key_info


def check_permission(api_key_info: dict, required_permission: str) -> bool:
    """
    Check if API key has required permission.

    Args:
        api_key_info: API key information dict from verify_api_key
        required_permission: Required permission (e.g., "domain:write", "scan:execute")

    Returns:
        True if has permission, False otherwise
    """
    permissions = api_key_info.get('permissions', [])
    return required_permission in permissions or '*' in permissions


def verify_api_key_sync(api_key: str, db: Optional[SQLModelManager] = None) -> tuple:
    """
    Synchronous API key verification (for WebSocket and non-async contexts).

    Uses constant-time comparison to prevent timing attacks.

    Args:
        api_key: Plain API key to verify
        db: Optional database manager. If None, creates a new one.

    Returns:
        Tuple of (is_valid: bool, api_key_info: dict or None, error_message: str or None)
    """
    if not api_key:
        return False, None, "API key is required"

    # Create DB manager if not provided
    db_owned = db is None
    if db_owned:
        db = SQLModelManager()
        try:
            db.initialize()
        except Exception as e:
            return False, None, f"Database error: {str(e)}"

    try:
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Verify against database (include inactive to check for revoked keys)
        api_key_info = db.get_api_key_by_hash(key_hash, include_inactive=True)

        # Constant-time comparison to prevent timing attacks
        if api_key_info:
            stored_hash = api_key_info.get('key_hash', '')
            # Use constant-time comparison
            if not secrets.compare_digest(key_hash, stored_hash):
                # Generate dummy comparison to maintain constant time
                dummy_hash = hashlib.sha256(b'dummy').hexdigest()
                secrets.compare_digest(key_hash, dummy_hash)
                return False, None, "Invalid API key"
        else:
            # Key not found - generate a dummy hash comparison to maintain constant time
            dummy_hash = hashlib.sha256(b'dummy').hexdigest()
            secrets.compare_digest(key_hash, dummy_hash)
            return False, None, "Invalid API key"

        # Check if key is active
        if not api_key_info.get('is_active', False):
            return False, None, "Invalid API key"  # Don't reveal if revoked

        # Check expiration if set
        if api_key_info.get('expires_at'):
            from datetime import datetime
            if datetime.utcnow() > api_key_info['expires_at']:
                return False, None, "Invalid API key"  # Don't reveal if expired

        return True, api_key_info, None

    finally:
        if db_owned:
            try:
                db.close()
            except:
                pass
