"""
Configuration management for OpenEASD.

Handles user preferences and default settings.

Author: Rathnakara G N
Company: Cybersecify
Created: October 2025
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any


class Config:
    """Manage OpenEASD configuration."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to config file (default: config/config.json in project)
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Default to project config directory
            # Get project root (assuming we're in src/utils/)
            project_root = Path(__file__).parent.parent.parent
            config_dir = project_root / 'config'
            config_dir.mkdir(exist_ok=True)
            self.config_path = config_dir / 'config.json'

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_config(self) -> None:
        """Save configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def get_default_organization(self) -> Optional[str]:
        """Get default organization."""
        return self.config.get('default_organization')

    def set_default_organization(self, org_name: str) -> None:
        """Set default organization."""
        self.config['default_organization'] = org_name
        self._save_config()

    def clear_default_organization(self) -> None:
        """Clear default organization."""
        if 'default_organization' in self.config:
            del self.config['default_organization']
            self._save_config()

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self.config[key] = value
        self._save_config()
