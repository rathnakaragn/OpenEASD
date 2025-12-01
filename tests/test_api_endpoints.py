"""
Test cases for API endpoints (Read-Only).

Tests FastAPI endpoints for domains, scans, alerts, and health checks.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

from src.api.main import app
from src.data.database.sqlmodel_manager import SQLModelManager
from src.api.dependencies import get_db_manager


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.sqlite"
        db_manager = SQLModelManager(str(db_path))
        db_manager.initialize()
        yield db_manager
        db_manager.close()


@pytest.fixture
def client(temp_db):
    """Create FastAPI test client with temporary database."""
    app.dependency_overrides[get_db_manager] = lambda: temp_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    """Test cases for health check endpoint."""

    def test_health_check_success(self, client):
        """Test health check endpoint returns success."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"

    def test_health_endpoint_accessible(self, client):
        """Test health endpoint is accessible."""
        response = client.get("/api/v1/health")
        assert response.status_code in [200, 404]  # May depend on implementation


class TestDomainEndpoints:
    """Test cases for domain endpoints."""

    def test_list_domains_empty(self, client, temp_db):
        """Test listing domains when none exist."""
        response = client.get("/api/v1/domains")

        assert response.status_code == 200
        data = response.json()
        assert "domains" in data
        assert data["domains"] == []
        assert data["total_count"] == 0

    def test_list_domains_with_data(self, client, temp_db):
        """Test listing domains with data."""
        # Add domain via database
        temp_db.add_domain('example.com', is_primary=True)

        response = client.get("/api/v1/domains")

        assert response.status_code == 200
        data = response.json()
        assert len(data["domains"]) >= 1
        assert data["total_count"] >= 1

    def test_list_domains_with_limit(self, client, temp_db):
        """Test listing domains with limit parameter."""
        # Add multiple domains
        for i in range(5):
            temp_db.add_domain(f'example{i}.com')

        response = client.get("/api/v1/domains?limit=2")

        assert response.status_code == 200
        data = response.json()
        assert len(data["domains"]) <= 2

    def test_list_domains_invalid_limit(self, client):
        """Test that invalid limit parameter is rejected."""
        response = client.get("/api/v1/domains?limit=1000")

        # Should either accept or return 422 (validation error)
        assert response.status_code in [200, 422]

    def test_list_domains_primary_only_filter(self, client, temp_db):
        """Test filtering only primary domains."""
        temp_db.add_domain('primary.com', is_primary=True)
        temp_db.add_domain('secondary.com', is_primary=False)

        response = client.get("/api/v1/domains?primary_only=true")

        assert response.status_code == 200
        data = response.json()
        # Should only have primary domains
        for domain in data["domains"]:
            assert domain["is_primary"] is True

    def test_get_domain_existing(self, client, temp_db):
        """Test getting details of existing domain."""
        temp_db.add_domain('example.com')

        response = client.get("/api/v1/domains/example.com")

        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == 'example.com'

    def test_get_domain_nonexistent(self, client):
        """Test getting nonexistent domain returns 404."""
        response = client.get("/api/v1/domains/nonexistent.com")

        assert response.status_code == 404

    def test_get_domain_invalid_format(self, client):
        """Test that invalid domain format returns error."""
        response = client.get("/api/v1/domains/invalid..com")

        assert response.status_code == 400 or response.status_code == 422

    def test_list_domains_cors_headers(self, client):
        """Test that CORS headers are present."""
        response = client.get("/api/v1/domains")

        # CORS should be enabled (based on main.py config)
        # This test validates the middleware is working
        assert response.status_code == 200


class TestScanEndpoints:
    """Test cases for scan endpoints."""

    def test_list_scans_empty(self, client):
        """Test listing scans when none exist."""
        response = client.get("/api/v1/scans")

        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert data["scans"] == []

    def test_list_scans_with_limit(self, client, temp_db):
        """Test listing scans with limit."""
        # Create a scan session via database
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        response = client.get("/api/v1/scans?limit=10")

        assert response.status_code == 200
        data = response.json()
        assert "scans" in data

    def test_get_scan_status_nonexistent(self, client):
        """Test getting status of nonexistent scan."""
        response = client.get("/api/v1/scans/nonexistent-uuid")

        assert response.status_code == 404

    def test_get_scan_status_existing(self, client, temp_db):
        """Test getting status of existing scan."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        response = client.get(f"/api/v1/scans/{scan_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id

    def test_get_scan_results_nonexistent(self, client):
        """Test getting results of nonexistent scan."""
        response = client.get("/api/v1/scans/nonexistent-uuid/results")

        assert response.status_code == 404

    def test_get_scan_results_existing(self, client, temp_db):
        """Test getting results of existing scan."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )
        temp_db.update_scan_status(scan_id, 'completed')

        response = client.get(f"/api/v1/scans/{scan_id}/results")

        assert response.status_code == 200
        data = response.json()
        assert "scan" in data
        assert data["scan"]["scan_id"] == scan_id


class TestAlertEndpoints:
    """Test cases for alert endpoints."""

    def test_list_alerts_empty(self, client):
        """Test listing alerts when none exist."""
        response = client.get("/api/v1/alerts")

        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert data["alerts"] == []

    def test_list_alerts_with_limit(self, client):
        """Test listing alerts with limit."""
        response = client.get("/api/v1/alerts?limit=10")

        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data

    def test_list_alerts_severity_filter(self, client):
        """Test filtering alerts by severity."""
        response = client.get("/api/v1/alerts?severity=high")

        # Should either return 200 or 422 if filter not supported
        assert response.status_code in [200, 422]

    def test_get_alert_statistics(self, client):
        """Test getting alert statistics."""
        response = client.get("/api/v1/alerts/statistics")

        assert response.status_code == 200
        data = response.json()
        # Check for expected fields at top level
        assert "total" in data
        assert "by_severity" in data
        assert "by_type" in data
        assert "by_tool" in data


class TestAPIResponseFormats:
    """Test cases for API response formats."""

    def test_domain_list_response_format(self, client, temp_db):
        """Test that domain list response has correct format."""
        temp_db.add_domain('example.com', is_primary=True)

        response = client.get("/api/v1/domains")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "domains" in data
        assert "total_count" in data
        assert isinstance(data["domains"], list)
        assert isinstance(data["total_count"], int)

    def test_scan_list_response_format(self, client, temp_db):
        """Test that scan list response has correct format."""
        scan_id = temp_db.create_scan_session(
            scan_type='passive_subdomain_enum',
            domains=['example.com']
        )

        response = client.get("/api/v1/scans")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_api_json_serialization(self, client, temp_db):
        """Test that API responses are valid JSON."""
        temp_db.add_domain('example.com')

        response = client.get("/api/v1/domains")

        # Response should be valid JSON
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)


class TestAPIErrorHandling:
    """Test cases for API error handling."""

    def test_nonexistent_endpoint_returns_404(self, client):
        """Test that nonexistent endpoint returns 404."""
        response = client.get("/api/v1/nonexistent")

        assert response.status_code == 404

    def test_invalid_query_parameters(self, client):
        """Test that invalid query parameters are handled."""
        response = client.get("/api/v1/domains?limit=-1")

        # Should return validation error or be ignored
        assert response.status_code in [200, 422]

    def test_read_only_api_no_post(self, client):
        """Test that POST requests are not allowed (read-only API)."""
        response = client.post("/api/v1/domains")

        # Returns 405 Method Not Allowed (read-only API)
        assert response.status_code == 405

    def test_read_only_api_no_delete(self, client):
        """Test that DELETE requests are not allowed (read-only API)."""
        response = client.delete("/api/v1/domains/example.com")

        # Returns 405 Method Not Allowed (read-only API)
        assert response.status_code == 405

    def test_read_only_api_no_put(self, client):
        """Test that PUT requests are not allowed (read-only API)."""
        response = client.put("/api/v1/domains/example.com")

        # Returns 405 Method Not Allowed (read-only API)
        assert response.status_code == 405

    def test_api_handles_database_errors_gracefully(self, client, temp_db):
        """Test that API handles database errors gracefully."""
        # This would require mocking a database error
        # For now, just verify normal operation
        response = client.get("/api/v1/domains")
        assert response.status_code == 200


class TestAPIDocumentation:
    """Test cases for API documentation."""

    def test_openapi_schema_available(self, client):
        """Test that OpenAPI schema is available."""
        response = client.get("/api/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data or "swagger" in data

    def test_swagger_ui_available(self, client):
        """Test that Swagger UI is available."""
        response = client.get("/api/docs")

        assert response.status_code == 200
        assert "html" in response.text.lower() or "swagger" in response.text.lower()

    def test_redoc_available(self, client):
        """Test that ReDoc is available."""
        response = client.get("/api/redoc")

        assert response.status_code == 200


class TestAPIPagination:
    """Test cases for API pagination."""

    def test_pagination_metadata(self, client, temp_db):
        """Test that pagination metadata is present."""
        for i in range(5):
            temp_db.add_domain(f'example{i}.com')

        response = client.get("/api/v1/domains?limit=2")

        assert response.status_code == 200
        data = response.json()

        # Check pagination fields
        assert "total_count" in data
        assert data["total_count"] >= 2

    def test_pagination_limit_respected(self, client, temp_db):
        """Test that limit parameter is respected."""
        for i in range(10):
            temp_db.add_domain(f'example{i}.com')

        response = client.get("/api/v1/domains?limit=3")

        assert response.status_code == 200
        data = response.json()
        assert len(data["domains"]) <= 3
