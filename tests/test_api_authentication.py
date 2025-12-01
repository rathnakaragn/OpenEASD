"""
Unit tests for API authentication and authorization.

Tests API key validation, permission checking, and security features.
"""

import pytest
import hashlib
import uuid
import secrets

# Fixtures are provided by conftest.py


class TestAPIKeyValidation:
    """Test API key validation."""

    def test_missing_api_key(self, client):
        """Test request without API key."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain}
        )

        assert response.status_code == 401
        assert "API key required" in response.json()["detail"]

    def test_invalid_api_key(self, client):
        """Test request with invalid API key."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain},
            headers={"X-API-Key": "invalid_key_that_does_not_exist"}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_valid_api_key(self, client, admin_key):
        """Test request with valid API key."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain},
            headers={"X-API-Key": admin_key}
        )

        # Should succeed (or fail for other reasons, but not auth)
        assert response.status_code != 401

    def test_api_key_case_sensitive(self, client, admin_key):
        """Test that API keys are case-sensitive."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        # Try with uppercase version
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain},
            headers={"X-API-Key": admin_key.upper()}
        )

        assert response.status_code == 401

    def test_api_key_whitespace_stripped(self, client, admin_key):
        """Test that whitespace is NOT stripped from API keys."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain},
            headers={"X-API-Key": f"  {admin_key}  "}
        )

        # Should fail - keys with whitespace should not match
        assert response.status_code == 401


class TestPermissionAuthorization:
    """Test permission-based authorization."""

    def test_admin_key_all_permissions(self, client, admin_key):
        """Test admin key has all permissions."""
        unique_domain1 = f"test{uuid.uuid4().hex[:8]}.com"
        unique_domain2 = f"test{uuid.uuid4().hex[:8]}.com"
        # Try domain write
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain1},
            headers={"X-API-Key": admin_key}
        )
        assert response.status_code != 403

        # Try scan execute
        response = client.post(
            "/api/v1/scans",
            json={"domain": unique_domain2},
            headers={"X-API-Key": admin_key}
        )
        assert response.status_code != 403

    def test_domain_writer_no_scan_permission(self, client, domain_writer_key):
        """Test domain writer cannot execute scans."""
        response = client.post(
            "/api/v1/scans",
            json={"domain": "test.com"},
            headers={"X-API-Key": domain_writer_key}
        )

        assert response.status_code == 403
        assert "scan:execute" in response.json()["detail"]

    def test_scan_executor_no_domain_permission(self, client, scan_executor_key):
        """Test scan executor cannot write domains."""
        response = client.post(
            "/api/v1/domains",
            json={"domain": "test.com"},
            headers={"X-API-Key": scan_executor_key}
        )

        assert response.status_code == 403
        assert "domain:write" in response.json()["detail"]

    def test_domain_writer_can_create_domains(self, client, domain_writer_key):
        """Test domain writer can create domains."""
        unique_domain = f"test{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain},
            headers={"X-API-Key": domain_writer_key}
        )

        assert response.status_code in [201, 400]  # 201 for success, 400 for validation

    def test_domain_writer_can_delete_domains(self, client, domain_writer_key, db_manager):
        """Test domain writer can delete domains."""
        # Create domain first
        unique_domain = f"deltest{uuid.uuid4().hex[:8]}.com"
        db_manager.add_domain(unique_domain, is_primary=False)

        response = client.delete(
            f"/api/v1/domains/{unique_domain}?force=true",
            headers={"X-API-Key": domain_writer_key}
        )

        assert response.status_code in [200, 400]

    def test_scan_executor_can_execute_scans(self, client, scan_executor_key, db_manager):
        """Test scan executor can execute scans."""
        # Create domain first
        unique_domain = f"scantest{uuid.uuid4().hex[:8]}.com"
        db_manager.add_domain(unique_domain, is_primary=False)

        response = client.post(
            "/api/v1/scans",
            json={"domain": unique_domain},
            headers={"X-API-Key": scan_executor_key}
        )

        assert response.status_code in [202, 400]

    def test_scan_executor_can_trigger_analysis(self, client, scan_executor_key, db_manager):
        """Test scan executor can trigger analysis."""
        # Create and complete a scan
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["test.com"]
        )
        db_manager.update_scan_status(scan_id, 'completed')

        response = client.post(
            f"/api/v1/scans/{scan_id}/analysis",
            headers={"X-API-Key": scan_executor_key}
        )

        assert response.status_code in [202, 400]


class TestRevokedKeyBehavior:
    """Test behavior with revoked API keys."""

    def test_revoked_key_rejected(self, client, db_manager):
        """Test that revoked keys are rejected."""
        # Create a key
        plain_key = secrets.token_urlsafe(32)
        hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

        result = db_manager.create_api_key(
            key_hash=hashed_key,
            name="revoke_test",
            permissions=["*"]
        )
        key_id = result["id"]

        unique_domain1 = f"test{uuid.uuid4().hex[:8]}.com"
        unique_domain2 = f"test{uuid.uuid4().hex[:8]}.com"

        # Use it successfully first
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain1},
            headers={"X-API-Key": plain_key}
        )
        assert response.status_code != 401

        # Revoke the key
        db_manager.revoke_api_key(key_id)

        # Try to use revoked key
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain2},
            headers={"X-API-Key": plain_key}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]


class TestSecurityHeaders:
    """Test security-related headers in responses."""

    # def test_rate_limit_headers_present(self, client, admin_key):
    #     """Test that rate limit headers are present."""
    #     response = client.post(
    #         "/api/v1/domains",
    #         json={"domain": "test.com"},
    #         headers={"X-API-Key": admin_key}
    #     )

    #     assert "X-RateLimit-Limit" in response.headers
    #     assert "X-RateLimit-Remaining" in response.headers

    def test_auth_error_headers(self, client):
        """Test that auth errors include proper headers."""
        response = client.post(
            "/api/v1/domains",
            json={"domain": "test.com"}
        )

        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers


class TestReadOperationsNoAuth:
    """Verify read operations don't require authentication."""

    def test_list_domains_no_auth(self, client):
        """Test listing domains without API key."""
        response = client.get("/api/v1/domains")

        assert response.status_code == 200
        assert "domains" in response.json()

    def test_list_scans_no_auth(self, client):
        """Test listing scans without API key."""
        response = client.get("/api/v1/scans")

        assert response.status_code == 200
        assert "scans" in response.json()

    def test_get_domain_no_auth(self, client, db_manager):
        """Test getting domain details without API key."""
        # Create a domain first
        unique_domain = f"readtest{uuid.uuid4().hex[:8]}.com"
        db_manager.add_domain(unique_domain, is_primary=False)

        response = client.get(f"/api/v1/domains/{unique_domain}")

        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == unique_domain
