"""
Unit tests for API write operations.

Tests POST, PATCH, DELETE endpoints for domains, scans, and analysis.
"""

import pytest
import json
import hashlib
import uuid
import secrets

# Fixtures are provided by conftest.py


class TestDomainWriteOperations:
    """Test domain management write endpoints."""

    def test_create_domain_success(self, client, test_api_key):
        """Test successful domain creation."""
        # Use unique domain name
        unique_domain = f"testdomain{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain, "is_primary": True},
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 201
        data = response.json()
        assert data["domain"] == unique_domain
        assert data["is_primary"] == True

    def test_create_domain_missing_auth(self, client):
        """Test domain creation without API key."""
        unique_domain = f"testdomain{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain, "is_primary": True}
        )

        assert response.status_code == 401
        assert "API key required" in response.json()["detail"]

    def test_create_domain_invalid_key(self, client):
        """Test domain creation with invalid API key."""
        unique_domain = f"testdomain{uuid.uuid4().hex[:8]}.com"
        response = client.post(
            "/api/v1/domains",
            json={"domain": unique_domain, "is_primary": True},
            headers={"X-API-Key": "invalid_key"}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_create_domain_insufficient_permissions(self, client, test_api_key_limited):
        """Test domain creation with insufficient permissions."""
        # This key doesn't have scan:execute permission
        response = client.post(
            "/api/v1/scans",
            json={"domain": "example.com"},
            headers={"X-API-Key": test_api_key_limited}
        )

        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    def test_update_domain_success(self, client, test_api_key, db_manager):
        """Test successful domain update."""
        # Use unique domain name
        unique_domain = f"updatetest{uuid.uuid4().hex[:8]}.com"
        # First create a domain
        db_manager.add_domain(unique_domain, is_primary=False)

        response = client.patch(
            f"/api/v1/domains/{unique_domain}",
            json={"is_primary": True},
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == unique_domain
        assert data["is_primary"] == True

    def test_update_domain_not_found(self, client, test_api_key):
        """Test updating non-existent domain."""
        unique_domain = f"nonexist{uuid.uuid4().hex[:8]}.com"
        response = client.patch(
            f"/api/v1/domains/{unique_domain}",
            json={"is_primary": True},
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 404

    def test_delete_domain_success(self, client, test_api_key, db_manager):
        """Test successful domain deletion."""
        # Use unique domain name
        unique_domain = f"deltest{uuid.uuid4().hex[:8]}.com"
        # First create a domain
        db_manager.add_domain(unique_domain, is_primary=True)

        response = client.delete(
            f"/api/v1/domains/{unique_domain}?force=true",
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "deleted" in data["message"].lower()

    def test_delete_domain_not_found(self, client, test_api_key):
        """Test deleting non-existent domain."""
        unique_domain = f"nonexist{uuid.uuid4().hex[:8]}.com"
        response = client.delete(
            f"/api/v1/domains/{unique_domain}?force=true",
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 404


class TestScanWriteOperations:
    """Test scan execution endpoints."""

    def test_execute_scan_success(self, client, test_api_key, db_manager):
        """Test successful scan execution."""
        # Use unique domain name
        unique_domain = f"scantest{uuid.uuid4().hex[:8]}.com"
        # Add domain first
        db_manager.add_domain(unique_domain, is_primary=True)

        response = client.post(
            "/api/v1/scans",
            json={"domain": unique_domain},
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 202
        data = response.json()
        assert data["domain"] == unique_domain
        assert data["status"] == "pending"
        assert "scan_id" in data

    def test_execute_scan_missing_auth(self, client):
        """Test scan execution without API key."""
        response = client.post(
            "/api/v1/scans",
            json={"domain": "example.com"}
        )

        assert response.status_code == 401

    def test_execute_scan_insufficient_permissions(self, client, test_api_key_limited):
        """Test scan execution with insufficient permissions."""
        response = client.post(
            "/api/v1/scans",
            json={"domain": "example.com"},
            headers={"X-API-Key": test_api_key_limited}
        )

        assert response.status_code == 403
        assert "scan:execute" in response.json()["detail"]

    def test_trigger_analysis_success(self, client, test_api_key, db_manager):
        """Test successful analysis trigger."""
        # Create a scan session
        scan_id = db_manager.create_scan_session(
            scan_type="passive_subdomain_enum",
            domains=["example.com"]
        )

        # Mark as completed
        db_manager.update_scan_status(scan_id, 'completed')

        response = client.post(
            f"/api/v1/scans/{scan_id}/analysis",
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "analyzing"

    def test_trigger_analysis_not_found(self, client, test_api_key):
        """Test analysis trigger on non-existent scan."""
        response = client.post(
            "/api/v1/scans/nonexistent_scan_id/analysis",
            headers={"X-API-Key": test_api_key}
        )

        assert response.status_code == 404





class TestAPIKeyManagement:
    """Test API key operations."""

    def test_create_api_key(self, db_manager):
        """Test API key creation."""
        plain_key = secrets.token_urlsafe(32)
        hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

        result = db_manager.create_api_key(
            key_hash=hashed_key,
            name="test_creation",
            permissions=["domain:write", "scan:execute"]
        )

        assert result["name"] == "test_creation"
        assert result["is_active"] == True
        assert "domain:write" in result["permissions"]

    def test_list_api_keys(self, db_manager):
        """Test API key listing."""
        # Create a key
        plain_key = secrets.token_urlsafe(32)
        hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()
        db_manager.create_api_key(
            key_hash=hashed_key,
            name="test_list",
            permissions=["*"]
        )

        keys = db_manager.list_api_keys()

        assert len(keys) > 0
        assert any(k["name"] == "test_list" for k in keys)

    def test_revoke_api_key(self, db_manager):
        """Test API key revocation."""
        # Create a key
        plain_key = secrets.token_urlsafe(32)
        hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()
        result = db_manager.create_api_key(
            key_hash=hashed_key,
            name="test_revoke",
            permissions=["*"]
        )
        key_id = result["id"]

        # Revoke it
        success = db_manager.revoke_api_key(key_id)

        assert success == True

        # Try to use revoked key
        revoked_key_info = db_manager.get_api_key_by_hash(hashed_key)
        assert revoked_key_info is None  # Should not be found


class TestReadOperationsUnaffected:
    """Ensure read operations still work correctly."""

    def test_list_domains_still_works(self, client):
        """Test that GET domains still works."""
        response = client.get("/api/v1/domains")

        assert response.status_code == 200
        data = response.json()
        assert "domains" in data
        assert "total_count" in data

    def test_list_scans_still_works(self, client):
        """Test that GET scans still works."""
        response = client.get("/api/v1/scans")

        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert "total" in data

    def test_health_check_still_works(self, client):
        """Test that health endpoint still works."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
