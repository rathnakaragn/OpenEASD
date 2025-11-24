"""
Configuration management for OpenEASD.

Handles loading settings from a default YAML file and a user-specific JSON override file.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

import os
import json
import yaml
from pathlib import Path
from typing import Optional, Dict, Any

def deep_merge(a, b):
    """
    Deeply merge two dictionaries, with b overriding a.
    """
    result = a.copy()
    for key, value in b.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

class Config:
    """Manage OpenEASD configuration."""

    def __init__(self, config_path: Optional[str] = None, recon_config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to user config file (default: config/config.json)
            recon_config_path: Path to default recon config file (default: config/recon_config.yaml)
        """
        project_root = Path(__file__).parent.parent.parent
        config_dir = project_root / 'config'
        config_dir.mkdir(exist_ok=True)

        self.config_path = Path(config_path) if config_path else config_dir / 'config.json'
        self.recon_config_path = Path(recon_config_path) if recon_config_path else config_dir / 'recon_config.yaml'

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load and merge configurations."""
        # Load default YAML config
        default_config = {}
        if self.recon_config_path.exists():
            try:
                with open(self.recon_config_path, 'r') as f:
                    default_config = yaml.safe_load(f)
            except (yaml.YAMLError, IOError):
                pass  # Ignore errors in default config

        # Load user JSON config
        user_config = {}
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass  # Ignore errors in user config

        # Merge configs, with user config taking precedence
        return deep_merge(default_config, user_config)

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
