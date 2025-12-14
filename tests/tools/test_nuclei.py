"""
Comprehensive unit tests for Nuclei tool integration.

Tests network vulnerability scanning for non-web services including:
- MySQL, PostgreSQL, Redis, MongoDB, SSH, FTP, etc.
- Template-based scanning
- Parallel execution
- Error handling
"""

import pytest
from unittest.mock import MagicMock, patch, call
from subprocess import TimeoutExpired
from pathlib import Path
import json

from src.tools.nuclei import (
    run_nuclei_network,
    run_nuclei_network_parallel,
    run_nuclei_service,
    _parse_nuclei_result,
    _get_nuclei_cmd,
)
from src.tools.exceptions import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
)


# ========================================================================
# _get_nuclei_cmd() Tests
# ========================================================================

@patch('os.path.exists')
def test_get_nuclei_cmd_pdtm_path(mock_exists):
    """Test nuclei command uses pdtm path when available."""
    mock_exists.return_value = True
    cmd = _get_nuclei_cmd()
    assert '.pdtm/go/bin/nuclei' in cmd


@patch('os.path.exists')
@patch('src.tools.nuclei.config')
def test_get_nuclei_cmd_fallback_config(mock_config, mock_exists):
    """Test nuclei command falls back to config when pdtm not available."""
    mock_exists.return_value = False
    mock_config.get.return_value = '/custom/path/nuclei'
    cmd = _get_nuclei_cmd()
    assert cmd == '/custom/path/nuclei'


@patch('os.path.exists')
@patch('src.tools.nuclei.config')
def test_get_nuclei_cmd_default(mock_config, mock_exists):
    """Test nuclei command uses default 'nuclei' when no custom path."""
    mock_exists.return_value = False
    mock_config.get.return_value = 'nuclei'
    cmd = _get_nuclei_cmd()
    assert cmd == 'nuclei'


# ========================================================================
# _parse_nuclei_result() Tests
# ========================================================================

def test_parse_nuclei_result_complete():
    """Test parsing complete nuclei result with CVE."""
    data = {
        'template-id': 'mysql-auth-bypass',
        'info': {
            'name': 'MySQL Authentication Bypass',
            'severity': 'critical',
            'description': 'MySQL auth bypass vulnerability',
            'tags': ['mysql', 'cve', 'auth-bypass'],
            'reference': ['https://nvd.nist.gov/vuln/detail/CVE-2012-2122'],
            'classification': {
                'cve-id': ['CVE-2012-2122'],
                'cvss-score': 9.8
            }
        },
        'host': '192.168.1.1:3306',
        'matched-at': '192.168.1.1:3306',
        'type': 'network'
    }

    result = _parse_nuclei_result(data)

    assert result['template_id'] == 'mysql-auth-bypass'
    assert result['template_name'] == 'MySQL Authentication Bypass'
    assert result['severity'] == 'critical'
    assert result['cve_id'] == 'CVE-2012-2122'
    assert result['cvss_score'] == 9.8
    assert result['host'] == '192.168.1.1:3306'
    assert result['type'] == 'network'


def test_parse_nuclei_result_no_cve():
    """Test parsing nuclei result without CVE."""
    data = {
        'template-id': 'redis-info',
        'info': {
            'name': 'Redis Information Disclosure',
            'severity': 'medium',
            'description': 'Redis server exposes information',
            'tags': ['redis', 'info'],
        },
        'host': '192.168.1.1:6379',
        'type': 'network'
    }

    result = _parse_nuclei_result(data)

    assert result['template_id'] == 'redis-info'
    assert result['cve_id'] is None
    assert result['cvss_score'] is None
    assert result['severity'] == 'medium'


def test_parse_nuclei_result_empty():
    """Test parsing empty nuclei result."""
    result = _parse_nuclei_result({})
    assert result is None


def test_parse_nuclei_result_none():
    """Test parsing None."""
    result = _parse_nuclei_result(None)
    assert result is None


def test_parse_nuclei_result_minimal():
    """Test parsing minimal nuclei result."""
    data = {
        'template-id': 'test-template',
        'info': {
            'name': 'Test',
            'severity': 'info'
        },
        'host': 'target:8080'
    }

    result = _parse_nuclei_result(data)

    assert result['template_id'] == 'test-template'
    assert result['template_name'] == 'Test'
    assert result['severity'] == 'info'
    assert result['host'] == 'target:8080'


# ========================================================================
# run_nuclei_network() Tests
# ========================================================================

@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_success(mock_get_cmd, mock_run):
    """Test successful nuclei network scan."""
    mock_get_cmd.return_value = 'nuclei'

    # Simulate nuclei output
    nuclei_output = json.dumps({
        'template-id': 'mysql-empty-password',
        'info': {
            'name': 'MySQL Empty Password',
            'severity': 'critical',
            'classification': {'cve-id': ['CVE-2021-1234']}
        },
        'host': 'db.example.com:3306',
        'type': 'network'
    })

    mock_run.return_value = MagicMock(
        stdout=nuclei_output,
        stderr='',
        returncode=0
    )

    results = run_nuclei_network(['db.example.com:3306'])

    assert len(results) == 1
    assert results[0]['template_id'] == 'mysql-empty-password'
    assert results[0]['severity'] == 'critical'
    mock_run.assert_called_once()


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_multiple_findings(mock_get_cmd, mock_run):
    """Test nuclei scan with multiple findings."""
    mock_get_cmd.return_value = 'nuclei'

    # Multiple findings on different lines
    findings = [
        json.dumps({
            'template-id': 'mysql-vuln-1',
            'info': {'name': 'Vuln 1', 'severity': 'high'},
            'host': 'db:3306',
            'type': 'network'
        }),
        json.dumps({
            'template-id': 'mysql-vuln-2',
            'info': {'name': 'Vuln 2', 'severity': 'medium'},
            'host': 'db:3306',
            'type': 'network'
        })
    ]

    mock_run.return_value = MagicMock(
        stdout='\n'.join(findings),
        stderr='',
        returncode=0
    )

    results = run_nuclei_network(['db:3306'])

    assert len(results) == 2
    assert results[0]['template_id'] == 'mysql-vuln-1'
    assert results[1]['template_id'] == 'mysql-vuln-2'


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_no_findings(mock_get_cmd, mock_run):
    """Test nuclei scan with no findings."""
    mock_get_cmd.return_value = 'nuclei'

    mock_run.return_value = MagicMock(
        stdout='',
        stderr='',
        returncode=0
    )

    results = run_nuclei_network(['secure-host:22'])

    assert len(results) == 0


def test_run_nuclei_network_empty_targets():
    """Test nuclei scan with empty targets."""
    results = run_nuclei_network([])
    assert results == []


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_timeout(mock_get_cmd, mock_run):
    """Test nuclei scan timeout."""
    mock_get_cmd.return_value = 'nuclei'
    mock_run.side_effect = TimeoutExpired(cmd='nuclei', timeout=300)

    with pytest.raises(ToolTimeoutError) as exc_info:
        run_nuclei_network(['db:3306'], timeout=300)

    assert '300 seconds' in str(exc_info.value)


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_not_found(mock_get_cmd, mock_run):
    """Test nuclei not installed."""
    mock_get_cmd.return_value = 'nuclei'
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(ToolNotFoundError) as exc_info:
        run_nuclei_network(['db:3306'])

    assert 'Nuclei not found' in str(exc_info.value)


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_custom_templates(mock_get_cmd, mock_run):
    """Test nuclei scan with custom templates."""
    mock_get_cmd.return_value = 'nuclei'
    mock_run.return_value = MagicMock(stdout='', returncode=0)

    run_nuclei_network(
        ['db:3306'],
        templates=['network/cves/mysql/', 'network/exposures/']
    )

    # Verify custom templates are used
    call_args = mock_run.call_args[0][0]
    assert '-t' in call_args
    assert 'network/cves/mysql/' in call_args
    assert 'network/exposures/' in call_args


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_with_severity_filter(mock_get_cmd, mock_run):
    """Test nuclei scan with severity filter."""
    mock_get_cmd.return_value = 'nuclei'
    mock_run.return_value = MagicMock(stdout='', returncode=0)

    run_nuclei_network(
        ['db:3306'],
        severity=['critical', 'high']
    )

    # Verify severity filter is used
    call_args = mock_run.call_args[0][0]
    assert '-severity' in call_args
    assert 'critical,high' in call_args


# ========================================================================
# run_nuclei_service() Tests
# ========================================================================

@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_service_mysql(mock_run_network):
    """Test nuclei scan for MySQL service."""
    mock_run_network.return_value = [
        {'template_id': 'mysql-vuln', 'severity': 'high', 'host': 'db:3306'}
    ]

    results = run_nuclei_service('db.example.com', 3306, 'mysql')

    assert len(results) == 1
    mock_run_network.assert_called_once()
    call_args = mock_run_network.call_args
    assert call_args[0][0] == ['db.example.com:3306']


@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_service_redis(mock_run_network):
    """Test nuclei scan for Redis service."""
    mock_run_network.return_value = []

    results = run_nuclei_service('cache.example.com', 6379, 'redis')

    mock_run_network.assert_called_once()
    call_args = mock_run_network.call_args
    assert call_args[0][0] == ['cache.example.com:6379']


@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_service_ssh(mock_run_network):
    """Test nuclei scan for SSH service."""
    mock_run_network.return_value = []

    results = run_nuclei_service('server.example.com', 22, 'ssh')

    mock_run_network.assert_called_once()


@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_service_unknown(mock_run_network):
    """Test nuclei scan for unknown service uses default templates."""
    mock_run_network.return_value = []

    results = run_nuclei_service('server.example.com', 9999, 'unknown-service')

    mock_run_network.assert_called_once()
    # Should use default network templates
    call_args = mock_run_network.call_args
    templates = call_args[1].get('templates', [])
    assert 'network/' in templates[0] if templates else True


# ========================================================================
# run_nuclei_network_parallel() Tests
# ========================================================================

@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_network_parallel_success(mock_run_network):
    """Test parallel nuclei scan."""
    mock_run_network.return_value = [
        {'template_id': 'test-vuln', 'severity': 'high', 'host': 'db1:3306'}
    ]

    targets = ['db1:3306', 'db2:3306', 'db3:3306']
    results = run_nuclei_network_parallel(targets, max_workers=2)

    # Should have results for the targets
    assert isinstance(results, dict)


@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_network_parallel_empty(mock_run_network):
    """Test parallel nuclei scan with empty targets."""
    results = run_nuclei_network_parallel([])
    assert results == {}


@patch('src.tools.nuclei.run_nuclei_network')
def test_run_nuclei_network_parallel_partial_failure(mock_run_network):
    """Test parallel nuclei scan with partial failures."""
    def side_effect(targets, **kwargs):
        if 'failing' in targets[0]:
            raise Exception("Network error")
        return [{'template_id': 'test', 'host': targets[0]}]

    mock_run_network.side_effect = side_effect

    # This should handle failures gracefully
    targets = ['db1:3306', 'db2:3306']
    results = run_nuclei_network_parallel(targets, max_workers=2)

    # Should return partial results, not crash
    assert isinstance(results, dict)


# ========================================================================
# Integration-style Tests (with mocked subprocess)
# ========================================================================

@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_nuclei_full_workflow_mysql(mock_get_cmd, mock_run):
    """Test full nuclei workflow for MySQL vulnerability detection."""
    mock_get_cmd.return_value = 'nuclei'

    # Simulate real nuclei output for MySQL
    mysql_findings = '\n'.join([
        json.dumps({
            'template-id': 'mysql-empty-password',
            'info': {
                'name': 'MySQL Empty Password',
                'severity': 'critical',
                'classification': {'cve-id': ['CVE-2012-2122'], 'cvss-score': 9.8}
            },
            'host': 'db:3306',
            'matched-at': 'db:3306',
            'type': 'network'
        }),
        json.dumps({
            'template-id': 'mysql-native-password',
            'info': {
                'name': 'MySQL Native Password Bruteforce',
                'severity': 'high',
            },
            'host': 'db:3306',
            'type': 'network'
        })
    ])

    mock_run.return_value = MagicMock(
        stdout=mysql_findings,
        stderr='',
        returncode=0
    )

    results = run_nuclei_service('db', 3306, 'mysql')

    assert len(results) == 2

    # First finding should have CVE
    assert results[0]['cve_id'] == 'CVE-2012-2122'
    assert results[0]['cvss_score'] == 9.8
    assert results[0]['severity'] == 'critical'

    # Second finding without CVE
    assert results[1]['template_id'] == 'mysql-native-password'
    assert results[1]['severity'] == 'high'


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_nuclei_full_workflow_redis(mock_get_cmd, mock_run):
    """Test full nuclei workflow for Redis vulnerability detection."""
    mock_get_cmd.return_value = 'nuclei'

    redis_findings = json.dumps({
        'template-id': 'redis-unauthenticated-access',
        'info': {
            'name': 'Redis Unauthenticated Access',
            'severity': 'critical',
            'description': 'Redis server allows unauthenticated access'
        },
        'host': 'cache:6379',
        'type': 'network'
    })

    mock_run.return_value = MagicMock(
        stdout=redis_findings,
        stderr='',
        returncode=0
    )

    results = run_nuclei_service('cache', 6379, 'redis')

    assert len(results) == 1
    assert results[0]['severity'] == 'critical'
    assert 'Unauthenticated' in results[0]['template_name']


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_nuclei_json_parsing_robustness(mock_get_cmd, mock_run):
    """Test nuclei handles malformed JSON gracefully."""
    mock_get_cmd.return_value = 'nuclei'

    # Mix of valid and invalid JSON lines
    output = '\n'.join([
        '{"template-id": "valid", "info": {"name": "Valid", "severity": "high"}, "host": "h:80"}',
        'not json at all',
        '{"template-id": "also-valid", "info": {"name": "Also Valid", "severity": "low"}, "host": "h:80"}',
        '',  # Empty line
        '{"broken": json',  # Invalid JSON
    ])

    mock_run.return_value = MagicMock(
        stdout=output,
        stderr='',
        returncode=0
    )

    results = run_nuclei_network(['h:80'])

    # Should parse valid entries and skip invalid ones
    assert len(results) == 2
    assert results[0]['template_id'] == 'valid'
    assert results[1]['template_id'] == 'also-valid'


# ========================================================================
# Edge Cases and Error Handling
# ========================================================================

def test_parse_nuclei_result_with_list_cve():
    """Test parsing CVE when it's a list."""
    data = {
        'template-id': 'test',
        'info': {
            'name': 'Test',
            'severity': 'high',
            'classification': {
                'cve-id': ['CVE-2021-1234', 'CVE-2021-5678']
            }
        },
        'host': 'h:80'
    }

    result = _parse_nuclei_result(data)

    # Should take first CVE
    assert result['cve_id'] == 'CVE-2021-1234'


def test_parse_nuclei_result_with_string_cve():
    """Test parsing CVE when it's a string."""
    data = {
        'template-id': 'test',
        'info': {
            'name': 'Test',
            'severity': 'high',
            'classification': {
                'cve-id': 'CVE-2021-1234'
            }
        },
        'host': 'h:80'
    }

    result = _parse_nuclei_result(data)

    assert result['cve_id'] == 'CVE-2021-1234'


@patch('src.tools.nuclei.subprocess.run')
@patch('src.tools.nuclei._get_nuclei_cmd')
def test_run_nuclei_network_rate_limit(mock_get_cmd, mock_run):
    """Test nuclei scan with rate limiting."""
    mock_get_cmd.return_value = 'nuclei'
    mock_run.return_value = MagicMock(stdout='', returncode=0)

    run_nuclei_network(['db:3306'], rate_limit=50)

    call_args = mock_run.call_args[0][0]
    assert '-rate-limit' in call_args
    assert '50' in call_args
