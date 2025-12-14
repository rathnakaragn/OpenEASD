"""
Configuration management for OpenEASD.

Handles loading settings from YAML configuration files with environment
variable overrides. The unified config.yaml is the primary configuration
source, with legacy files (recon_config.yaml, analysis_config.yaml) merged
for backward compatibility.

Configuration Priority (highest to lowest):
1. Environment variables (OPENEASD_*)
2. User config (config/config.json)
3. Unified config (config/config.yaml)
4. Legacy configs (config/recon_config.yaml, config/analysis_config.yaml)

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
Updated: December 2025 - Added unified config support
"""

import os
import json
import yaml
from pathlib import Path
from typing import Optional, Dict, Any

def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deeply merge two dictionaries, with b overriding a.

    Args:
        a: Base dictionary
        b: Override dictionary (takes precedence)

    Returns:
        Merged dictionary with nested structures combined
    """
    result = a.copy()
    for key, value in b.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """Load a YAML file safely."""
    if path.exists():
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, IOError):
            pass
    return {}


def _load_json_file(path: Path) -> Dict[str, Any]:
    """Load a JSON file safely."""
    if path.exists():
        try:
            with open(path, 'r') as f:
                return json.load(f) or {}
        except (json.JSONDecodeError, IOError):
            pass
    return {}


class Config:
    """
    Manage OpenEASD configuration.

    Loads configuration from multiple sources in order of precedence:
    1. Environment variables (OPENEASD_*)
    2. User config (config.json)
    3. Unified config (config.yaml) - PRIMARY
    4. Legacy configs (recon_config.yaml, analysis_config.yaml)

    Usage:
        config = Config()
        db_path = config.get('database.database_path', 'data/openeasd.db')
        api_port = config.get('api.port', 8000)
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        recon_config_path: Optional[str] = None
    ):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to user config file (default: config/config.json)
            recon_config_path: Path to legacy recon config (default: config/recon_config.yaml)
        """
        project_root = Path(__file__).parent.parent.parent
        config_dir = project_root / 'config'
        config_dir.mkdir(exist_ok=True)

        # Path to unified config (primary)
        self.unified_config_path = config_dir / 'config.yaml'

        # Path to user overrides
        self.config_path = Path(config_path) if config_path else config_dir / 'config.json'

        # Paths to legacy configs (for backward compatibility)
        self.recon_config_path = (
            Path(recon_config_path) if recon_config_path
            else config_dir / 'recon_config.yaml'
        )
        self.analysis_config_path = config_dir / 'analysis_config.yaml'

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load and merge configurations from all sources.

        Loading order (later sources override earlier):
        1. Legacy recon_config.yaml
        2. Legacy analysis_config.yaml
        3. Unified config.yaml (PRIMARY)
        4. User config.json (overrides)
        5. Environment variables (highest priority)
        """
        config = {}

        # 1. Load legacy recon config (backward compatibility)
        recon_config = _load_yaml_file(self.recon_config_path)
        config = deep_merge(config, recon_config)

        # 2. Load legacy analysis config (backward compatibility)
        analysis_config = _load_yaml_file(self.analysis_config_path)
        config = deep_merge(config, analysis_config)

        # 3. Load unified config (PRIMARY - should have everything)
        unified_config = _load_yaml_file(self.unified_config_path)
        config = deep_merge(config, unified_config)

        # 4. Load user config overrides
        user_config = _load_json_file(self.config_path)
        config = deep_merge(config, user_config)

        # 5. Apply environment variable overrides
        config = self._apply_env_overrides(config)

        return config

    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides.

        Environment variables with OPENEASD_ prefix override config values.
        Use double underscore for nested keys: OPENEASD_API__PORT=8080

        Examples:
            OPENEASD_API__PORT=9000 -> api.port = 9000
            OPENEASD_DATABASE__DATABASE_PATH=/tmp/test.db -> database.database_path
        """
        prefix = 'OPENEASD_'

        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Convert OPENEASD_API__PORT to ['api', 'port']
                config_key = key[len(prefix):].lower().replace('__', '.')
                keys = config_key.split('.')

                # Navigate to parent and set value
                d = config
                for k in keys[:-1]:
                    d = d.setdefault(k, {})

                # Try to parse value as appropriate type
                parsed_value = self._parse_env_value(value)
                d[keys[-1]] = parsed_value

        return config

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # JSON (for complex values)
        if value.startswith('{') or value.startswith('['):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass

        return value

    def _save_user_config(self) -> None:
        """Save user configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        # Extract only the user-overridden values to save
        default_config = {}
        if self.recon_config_path.exists():
            try:
                with open(self.recon_config_path, 'r') as f:
                    default_config = yaml.safe_load(f)
            except (yaml.YAMLError, IOError):
                pass
        
        user_overrides = {}
        for key, value in self.config.items():
            if key not in default_config or default_config[key] != value:
                user_overrides[key] = value

        with open(self.config_path, 'w') as f:
            json.dump(user_overrides, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        Access nested keys using dot notation (e.g., 'database.max_connections').
        """
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value in the user config.
        Access nested keys using dot notation.
        """
        keys = key.split('.')
        d = self.config
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        self._save_user_config()
