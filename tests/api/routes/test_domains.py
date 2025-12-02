
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from src.api.main import app
from src.api.dependencies import get_domain_service
from src.services.exceptions import DomainNotFound, InvalidDomainFormat

client = TestClient(app)

# A sample domain that conforms to the DomainResponse schema
sample_domain = {
    "domain": "example.com",
    "is_primary": True,
    "scan_count": 5,
    "created_at": "2025-01-01T12:00:00",
    "updated_at": "2025-01-01T12:00:00",
    "last_scanned_at": "2025-01-01T12:00:00"
}

@pytest.fixture
def mock_domain_service():
    """Fixture for a mocked domain service."""
    service = MagicMock()
    service.list_domains.return_value = {'domains': [sample_domain], 'total_count': 1, 'has_more': False}
    service.get_domain.return_value = sample_domain
    return service

def test_list_domains(mock_domain_service):
    """Test the endpoint for listing domains."""
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get("/api/v1/domains")
    
    assert response.status_code == 200
    mock_domain_service.list_domains.assert_called()
    assert response.json()['total_count'] == 1
    assert response.json()['domains'][0]['domain'] == sample_domain['domain']
    
    app.dependency_overrides = {}

def test_list_domains_with_params(mock_domain_service):
    """Test listing domains with query parameters."""
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service

    response = client.get("/api/v1/domains?limit=10&primary_only=true")
    
    assert response.status_code == 200
    mock_domain_service.list_domains.assert_called_with(limit=10, primary_only=True)
    
    app.dependency_overrides = {}

def test_list_domains_error(mock_domain_service):
    """Test error handling when listing domains."""
    mock_domain_service.list_domains.side_effect = Exception("Service error")
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get("/api/v1/domains")
    
    assert response.status_code == 500
    assert "Failed to list domains" in response.text
    
    app.dependency_overrides = {}

def test_get_domain_by_name(mock_domain_service):
    """Test retrieving a single domain by its name."""
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get(f"/api/v1/domains/{sample_domain['domain']}")
    
    assert response.status_code == 200
    mock_domain_service.get_domain.assert_called_with(sample_domain['domain'])
    assert response.json()['domain'] == sample_domain['domain']
    
    app.dependency_overrides = {}

def test_get_domain_not_found(mock_domain_service):
    """Test retrieving a non-existent domain."""
    mock_domain_service.get_domain.side_effect = DomainNotFound
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get("/api/v1/domains/not-real.com")
    
    assert response.status_code == 404
    
    app.dependency_overrides = {}

def test_get_domain_invalid_format(mock_domain_service):
    """Test retrieving a domain with an invalid format."""
    mock_domain_service.get_domain.side_effect = InvalidDomainFormat
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get("/api/v1/domains/invalid-domain")
    
    assert response.status_code == 400
    
    app.dependency_overrides = {}

def test_get_domain_generic_error(mock_domain_service):
    """Test a generic error when retrieving a domain."""
    mock_domain_service.get_domain.side_effect = Exception("Generic error")
    app.dependency_overrides[get_domain_service] = lambda: mock_domain_service
    
    response = client.get("/api/v1/domains/any.com")
    
    assert response.status_code == 500
    assert "Failed to retrieve domain details" in response.text
    
    app.dependency_overrides = {}
