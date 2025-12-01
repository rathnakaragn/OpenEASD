
import pytest
from datetime import datetime
from pydantic import ValidationError
import pydantic_core
from src.data.models.alert import SecurityAlert

class TestSecurityAlertModel:
    """Test cases for the SecurityAlert SQLModel."""

    def test_security_alert_creation(self):
        """Test that a SecurityAlert instance can be created with all fields."""
        alert_id = "alert-123"
        domain = "example.com"
        scan_id = "scan-456"
        vulnerability_type = "XSS"
        severity = "high"
        description = "Reflected XSS found"
        remediation = "Sanitize user input"
        tool_source = "manual"
        discovered_at = datetime(2023, 1, 1, 10, 0, 0)

        alert = SecurityAlert(
            id=alert_id,
            domain=domain,
            scan_id=scan_id,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            remediation=remediation,
            tool_source=tool_source,
            discovered_at=discovered_at
        )

        assert alert.id == alert_id
        assert alert.domain == domain
        assert alert.scan_id == scan_id
        assert alert.vulnerability_type == vulnerability_type
        assert alert.severity == severity
        assert alert.description == description
        assert alert.remediation == remediation
        assert alert.tool_source == tool_source
        assert alert.discovered_at == discovered_at

    def test_security_alert_creation_defaults(self):
        """Test that a SecurityAlert instance can be created with default values."""
        alert = SecurityAlert(
            id="alert-789",
            domain="test.com",
            vulnerability_type="SQLi",
            severity="critical"
        )

        assert alert.id == "alert-789"
        assert alert.domain == "test.com"
        assert alert.scan_id is None
        assert alert.vulnerability_type == "SQLi"
        assert alert.severity == "critical"
        assert alert.description is None
        assert alert.remediation is None
        assert alert.tool_source is None
        assert isinstance(alert.discovered_at, datetime)


