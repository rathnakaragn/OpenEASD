"""
Tests for the CLI output formatters in src/cli/formatters.py.
"""
import json
import pytest
from src.cli.formatters import format_output

def test_format_json_output():
    """Test that data is correctly formatted as a JSON string."""
    data = {"key": "value", "items": [1, 2]}
    result = format_output(data, 'json')
    # Load the output back to verify it's valid JSON
    loaded = json.loads(result)
    assert loaded == data

def test_format_table_for_domains():
    """Test the table formatter for a list of domains."""
    data = {
        'domains': [
            {'domain': 'example.com', 'is_primary': True, 'scan_count': 5, 'last_scanned_at': '2023-10-27T10:00:00'},
            {'domain': 'test.com', 'is_primary': False, 'scan_count': 0, 'last_scanned_at': None}
        ],
        'total_count': 2
    }
    result = format_output(data, 'table')
    assert "Domains" in result
    assert "example.com" in result
    assert "test.com" in result
    assert "✓" in result
    assert "Never" in result

def test_format_table_for_detailed_domains():
    """Test the detailed table formatter for domains."""
    data = {
        'domains': [{'domain': 'example.com', 'is_primary': True, 'subdomain_count': 120}],
        'show_details': True
    }
    result = format_output(data, 'table')
    assert "Domain Details - example.com" in result
    assert "Total Subdomains: 120" in result

def test_format_table_for_scan_history():
    """Test the table formatter for scan history."""
    data = {
        'type': 'history',
        'scans': [{
            'domain': 'example.com', 'status': 'completed', 'total_subdomains': 50,
            'first_scan': '2023-10-27T10:00:00', 'last_scan': '2023-10-28T10:00:00'
        }]
    }
    result = format_output(data, 'table')
    assert "Scan History" in result
    assert "example.com" in result
    assert "completed" in result
    assert "50" in result

def test_format_table_for_scan_list():
    """Test the table formatter for the list of all scan sessions."""
    data = {
        'type': 'scan_list',
        'scans': [{
            'scan_id': 'test-scan-id-123', 'tool_name': 'subfinder', 'domain': 'example.com',
            'status': 'completed', 'findings_count': 150,
            'start_time': '2023-10-27T10:00:00', 'end_time': '2023-10-27T10:05:00'
        }]
    }
    result = format_output(data, 'table')
    assert "All Scan Sessions" in result
    assert "test-scan-id-123" in result
    assert "subfinder" in result
    assert "150" in result
    assert "300s" in result # Check duration calculation

def test_format_table_for_scan_results():
    """Test the table formatter for individual scan results."""
    data = {
        'type': 'scan_results',
        'scan': {'domain': 'example.com', 'scan_id': 'xyz', 'status': 'completed', 'total_subdomains': 3},
        'summary': {'active_subdomains': 2, 'open_ports': 1},
        'subdomains': ['a.example.com', 'b.example.com', 'c.example.com'],
        'active_subdomains': ['a.example.com', 'b.example.com'],
        'open_ports': [{'subdomain': 'a.example.com', 'port': 443}]
    }
    result = format_output(data, 'table')
    assert "Scan Results: example.com" in result
    assert "Total Subdomains Discovered: 3" in result
    assert "Active Subdomains (2):" in result
    assert "Open Ports (1):" in result
    assert "a.example.com" in result
    assert "443" in result

def test_format_csv_for_scan_results():
    """Test the CSV formatter for scan results."""
    data = {
        'type': 'scan_results',
        'subdomains': ['a.example.com', 'b.example.com'],
        'ports': [{'subdomain': 'a.example.com', 'port': 443}]
    }
    result = format_output(data, 'csv')
    assert "# Subdomains" in result
    assert "a.example.com" in result
    assert "# Ports" in result
    assert "443" in result

def test_format_txt_for_scan_results():
    """Test the TXT formatter for scan results."""
    data = {
        'type': 'scan_results',
        'subdomains': ['a.example.com', 'b.example.com']
    }
    result = format_output(data, 'txt')
    expected = "a.example.com\nb.example.com"
    # Strip trailing newline for comparison
    assert result.strip() == expected
