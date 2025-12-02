"""
Analysis Layer configuration management.

Loads and manages analysis-specific configuration from analysis_config.yaml.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List


class AnalysisConfig:
    """Manages analysis layer configuration."""

    def __init__(self, config_path: str = None):
        """
        Initialize analysis configuration.

        Args:
            config_path: Path to analysis_config.yaml (optional)
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "analysis_config.yaml"

        self.config_path = Path(config_path)
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            # Return default configuration if file doesn't exist
            return self._get_default_config()

        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'analysis': {
                'enabled': True,
                'auto_analyze_on_scan': False,  # Disabled by default for safety
                'batch_analysis_enabled': False,
                'scoring': {
                    'algorithm': 'deterministic',
                    'base_score_weight': 0.4,
                    'context_score_weight': 0.4,
                    'exposure_score_weight': 0.2,
                    'critical_threshold': 80,
                    'high_threshold': 60,
                    'medium_threshold': 40,
                    'low_threshold': 20
                },
                'detectors': {
                    'port_detector': {
                        'enabled': True,
                        'high_risk_ports': [21, 23, 3389, 5900, 5432, 3306, 27017],
                        'medium_risk_ports': [8080, 8443, 9090]
                    }
                },
                'performance': {
                    'max_concurrent_detectors': 5,
                    'analysis_timeout': 600,
                    'batch_size': 100
                }
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'analysis.scoring.algorithm')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def is_enabled(self) -> bool:
        """Check if analysis is enabled."""
        return self.get('analysis.enabled', True)

    def is_auto_analyze_enabled(self) -> bool:
        """Check if auto-analysis on scan is enabled."""
        return self.get('analysis.auto_analyze_on_scan', False)

    def get_high_risk_ports(self) -> List[int]:
        """Get list of high-risk ports."""
        return self.get('analysis.detectors.port_detector.high_risk_ports', [])

    def get_medium_risk_ports(self) -> List[int]:
        """Get list of medium-risk ports."""
        return self.get('analysis.detectors.port_detector.medium_risk_ports', [])

    def get_database_ports(self) -> List[int]:
        """Get list of database ports."""
        return self.get('analysis.detectors.port_detector.database_ports',
                       [3306, 5432, 27017, 6379, 1433, 5984, 9042, 7000, 7001])

    def get_admin_ports(self) -> List[int]:
        """Get list of admin interface ports."""
        return self.get('analysis.detectors.port_detector.admin_ports',
                       [2082, 2083, 2086, 2087, 8443, 10000])

    def get_remote_access_ports(self) -> List[int]:
        """Get list of remote access service ports."""
        return self.get('analysis.detectors.port_detector.remote_access_ports',
                       [21, 22, 23, 3389, 5900, 5901])

    def get_unencrypted_protocols(self) -> Dict[int, Dict[str, Any]]:
        """Get unencrypted protocols configuration."""
        config = self.get('analysis.detectors.port_detector.unencrypted_protocols', {})
        # Convert string keys to int if loaded from YAML
        result = {}
        for port, info in config.items():
            try:
                result[int(port)] = info
            except (ValueError, TypeError):
                continue
        return result

    # Service Detector configuration methods
    def get_critical_services(self) -> List[str]:
        """Get list of critical services (databases, etc.)."""
        return self.get('analysis.detectors.service_detector.critical_services',
                       ['mysql', 'postgresql', 'mongodb', 'redis', 'memcached',
                        'elasticsearch', 'cassandra', 'couchdb', 'mariadb', 'oracle', 'mssql'])

    def get_high_risk_services(self) -> List[str]:
        """Get list of high-risk services."""
        return self.get('analysis.detectors.service_detector.high_risk_services',
                       ['telnet', 'ftp', 'rsh', 'rlogin', 'vnc', 'rdp', 'smb', 'netbios'])

    def get_medium_risk_services(self) -> List[str]:
        """Get list of medium-risk services."""
        return self.get('analysis.detectors.service_detector.medium_risk_services',
                       ['ssh', 'smtp', 'dns', 'snmp', 'ldap', 'nfs', 'rpc'])

    def get_severity_thresholds(self) -> Dict[str, int]:
        """Get severity threshold mapping."""
        return {
            'critical': self.get('analysis.scoring.critical_threshold', 80),
            'high': self.get('analysis.scoring.high_threshold', 60),
            'medium': self.get('analysis.scoring.medium_threshold', 40),
            'low': self.get('analysis.scoring.low_threshold', 20)
        }


# Global configuration instance
_config = None


def get_analysis_config() -> AnalysisConfig:
    """Get or create global analysis configuration instance."""
    global _config
    if _config is None:
        _config = AnalysisConfig()
    return _config
