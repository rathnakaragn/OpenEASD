"""
OpenEASD Recon Layer - Configuration Management
6-Layer Architecture - Recon Layer

Configuration management for reconnaissance tools and workflows.
Provides centralized configuration with validation and defaults.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
import logging


@dataclass
class ToolConfig:
    """Configuration for individual reconnaissance tools."""
    enabled: bool = True
    executable_path: Optional[str] = None
    timeout: int = 300  # seconds
    retries: int = 3
    rate_limit: Optional[int] = None  # requests per second
    options: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.options is None:
            self.options = {}


@dataclass
class SubfinderConfig(ToolConfig):
    """Subfinder-specific configuration."""
    all_sources: bool = True
    active: bool = False
    verbose: bool = False
    max_time: int = 10  # minutes
    threads: int = 10
    sources: Optional[List[str]] = None
    exclude_sources: Optional[List[str]] = None
    recursive: bool = False


@dataclass
class NmapConfig(ToolConfig):
    """Nmap-specific configuration."""
    scan_type: str = "sS"  # SYN scan
    top_ports: Optional[int] = 1000
    port_range: Optional[str] = None
    timing: str = "T4"
    version_detection: bool = True
    os_detection: bool = False
    script_scan: bool = True
    scripts: Optional[List[str]] = None
    aggressive: bool = False


@dataclass
class NaabuConfig(ToolConfig):
    """Naabu-specific configuration."""
    top_ports: int = 1000
    ports: Optional[str] = None
    exclude_ports: Optional[str] = None
    verify: bool = True
    ping: bool = False
    scan_type: str = "syn"  # syn or connect
    threads: int = 25


@dataclass
class WhoisConfig(ToolConfig):
    """WHOIS-specific configuration."""
    follow_referrals: bool = True
    server: Optional[str] = None
    port: int = 43
    raw: bool = False


@dataclass
class WorkflowConfig:
    """Workflow execution configuration."""
    max_concurrent_tools: int = 3
    enable_rate_limiting: bool = True
    default_timeout: int = 1800  # 30 minutes
    auto_expand_targets: bool = True
    store_raw_output: bool = True
    parallel_execution: bool = True
    fail_fast: bool = False


@dataclass
class DatabaseConfig:
    """Database configuration."""
    database_path: Optional[str] = None
    max_connections: int = 10
    connection_timeout: float = 30.0
    query_timeout: float = 60.0
    enable_metrics: bool = True


@dataclass
class ReconConfig:
    """Master configuration for the Recon Layer."""
    # Tool configurations
    subfinder: SubfinderConfig = None
    nmap: NmapConfig = None
    naabu: NaabuConfig = None
    whois: WhoisConfig = None
    
    # Workflow configuration
    workflow: WorkflowConfig = None
    
    # Database configuration
    database: DatabaseConfig = None
    
    # Global settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    temp_directory: str = "/tmp/openeasd"
    
    def __post_init__(self):
        """Initialize default configurations if not provided."""
        if self.subfinder is None:
            self.subfinder = SubfinderConfig()
        if self.nmap is None:
            self.nmap = NmapConfig()
        if self.naabu is None:
            self.naabu = NaabuConfig()
        if self.whois is None:
            self.whois = WhoisConfig()
        if self.workflow is None:
            self.workflow = WorkflowConfig()
        if self.database is None:
            self.database = DatabaseConfig()


class ConfigManager:
    """
    Configuration manager for the Recon Layer.
    
    Features:
    - YAML/JSON configuration file support
    - Environment variable overrides
    - Configuration validation
    - Default configuration generation
    - Runtime configuration updates
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = logging.getLogger(f"{__name__}.ConfigManager")
        self.config_path = config_path
        self._config: Optional[ReconConfig] = None
        self._environment_overrides = {}
        
        # Load configuration
        self.load_configuration()

    def load_configuration(self) -> None:
        """Load configuration from file and environment variables."""
        try:
            # Start with default configuration
            config_dict = self._get_default_config()
            
            # Load from file if provided
            if self.config_path and Path(self.config_path).exists():
                file_config = self._load_from_file(self.config_path)
                config_dict = self._deep_merge(config_dict, file_config)
            
            # Apply environment variable overrides
            env_overrides = self._load_environment_overrides()
            if env_overrides:
                config_dict = self._deep_merge(config_dict, env_overrides)
                self._environment_overrides = env_overrides
            
            # Convert to ReconConfig object
            self._config = self._dict_to_config(config_dict)
            
            # Validate configuration
            self._validate_configuration()
            
            self.logger.info("Configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            # Fall back to default configuration
            self._config = ReconConfig()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration as dictionary."""
        default_config = ReconConfig()
        return asdict(default_config)

    def _load_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML or JSON file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        with open(path, 'r') as file:
            if path.suffix.lower() in ['.yml', '.yaml']:
                return yaml.safe_load(file) or {}
            elif path.suffix.lower() == '.json':
                return json.load(file)
            else:
                raise ValueError(f"Unsupported configuration file format: {path.suffix}")

    def _load_environment_overrides(self) -> Dict[str, Any]:
        """
        Load configuration overrides from environment variables.
        
        Environment variables should be prefixed with OPENEASD_RECON_
        and use double underscores for nesting (e.g., OPENEASD_RECON_SUBFINDER__TIMEOUT)
        
        Returns:
            Environment override dictionary
        """
        overrides = {}
        prefix = "OPENEASD_RECON_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Remove prefix and convert to nested structure
                config_path = key[len(prefix):].lower().split('__')
                
                # Convert value to appropriate type
                typed_value = self._convert_env_value(value)
                
                # Set nested value
                current = overrides
                for part in config_path[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[config_path[-1]] = typed_value
        
        return overrides

    def _convert_env_value(self, value: str) -> Any:
        """
        Convert environment variable string to appropriate type.
        
        Args:
            value: String value from environment variable
            
        Returns:
            Converted value
        """
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Try JSON (for lists/dicts)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
        
        # Return as string
        return value

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            override: Override dictionary
            
        Returns:
            Merged dictionary
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

    def _dict_to_config(self, config_dict: Dict[str, Any]) -> ReconConfig:
        """
        Convert configuration dictionary to ReconConfig object.
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            ReconConfig object
        """
        # Extract tool configurations
        subfinder_config = SubfinderConfig(**config_dict.get('subfinder', {}))
        nmap_config = NmapConfig(**config_dict.get('nmap', {}))
        naabu_config = NaabuConfig(**config_dict.get('naabu', {}))
        whois_config = WhoisConfig(**config_dict.get('whois', {}))
        
        # Extract workflow configuration
        workflow_config = WorkflowConfig(**config_dict.get('workflow', {}))
        
        # Extract database configuration
        database_config = DatabaseConfig(**config_dict.get('database', {}))
        
        # Create main configuration
        return ReconConfig(
            subfinder=subfinder_config,
            nmap=nmap_config,
            naabu=naabu_config,
            whois=whois_config,
            workflow=workflow_config,
            database=database_config,
            log_level=config_dict.get('log_level', 'INFO'),
            log_file=config_dict.get('log_file'),
            temp_directory=config_dict.get('temp_directory', '/tmp/openeasd')
        )

    def _validate_configuration(self) -> None:
        """Validate configuration values."""
        if not self._config:
            raise ValueError("Configuration not loaded")
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self._config.log_level not in valid_log_levels:
            self.logger.warning(f"Invalid log level: {self._config.log_level}, using INFO")
            self._config.log_level = 'INFO'
        
        # Validate timeout values
        if self._config.subfinder.timeout <= 0:
            self.logger.warning("Subfinder timeout must be positive, using default")
            self._config.subfinder.timeout = 300
        
        if self._config.nmap.timeout <= 0:
            self.logger.warning("Nmap timeout must be positive, using default")
            self._config.nmap.timeout = 1800
        
        # Validate port specifications
        if self._config.naabu.top_ports and self._config.naabu.top_ports <= 0:
            self.logger.warning("Naabu top_ports must be positive, using default")
            self._config.naabu.top_ports = 1000
        
        # Validate workflow settings
        if self._config.workflow.max_concurrent_tools <= 0:
            self.logger.warning("max_concurrent_tools must be positive, using default")
            self._config.workflow.max_concurrent_tools = 3
        
        # Create temp directory if needed
        temp_path = Path(self._config.temp_directory)
        try:
            temp_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.warning(f"Cannot create temp directory {temp_path}: {e}")
            self._config.temp_directory = "/tmp"

    def get_config(self) -> ReconConfig:
        """
        Get the current configuration.
        
        Returns:
            Current ReconConfig object
        """
        if not self._config:
            raise RuntimeError("Configuration not loaded")
        return self._config

    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """
        Get configuration for a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool configuration object
        """
        config = self.get_config()
        
        tool_configs = {
            'subfinder': config.subfinder,
            'nmap': config.nmap,
            'naabu': config.naabu,
            'whois': config.whois
        }
        
        if tool_name not in tool_configs:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        return tool_configs[tool_name]

    def update_tool_config(self, tool_name: str, updates: Dict[str, Any]) -> None:
        """
        Update configuration for a specific tool.
        
        Args:
            tool_name: Name of the tool
            updates: Dictionary of updates to apply
        """
        tool_config = self.get_tool_config(tool_name)
        
        for key, value in updates.items():
            if hasattr(tool_config, key):
                setattr(tool_config, key, value)
            else:
                self.logger.warning(f"Unknown configuration key for {tool_name}: {key}")

    def save_configuration(self, file_path: Optional[str] = None) -> None:
        """
        Save current configuration to file.
        
        Args:
            file_path: Path to save configuration (uses original path if not provided)
        """
        if not self._config:
            raise RuntimeError("Configuration not loaded")
        
        save_path = file_path or self.config_path
        if not save_path:
            raise ValueError("No file path specified for saving configuration")
        
        config_dict = asdict(self._config)
        path = Path(save_path)
        
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as file:
            if path.suffix.lower() in ['.yml', '.yaml']:
                yaml.dump(config_dict, file, default_flow_style=False, indent=2)
            elif path.suffix.lower() == '.json':
                json.dump(config_dict, file, indent=2)
            else:
                raise ValueError(f"Unsupported configuration file format: {path.suffix}")
        
        self.logger.info(f"Configuration saved to {save_path}")

    def generate_sample_config(self, output_path: str) -> None:
        """
        Generate a sample configuration file with comments.
        
        Args:
            output_path: Path to save sample configuration
        """
        sample_config = {
            "# OpenEASD Recon Layer Configuration": None,
            "log_level": "INFO",
            "log_file": "/var/log/openeasd/recon.log",
            "temp_directory": "/tmp/openeasd",
            
            "workflow": {
                "max_concurrent_tools": 3,
                "enable_rate_limiting": True,
                "default_timeout": 1800,
                "auto_expand_targets": True,
                "store_raw_output": True,
                "parallel_execution": True,
                "fail_fast": False
            },
            
            "database": {
                "database_path": "data/openeasd.db",
                "max_connections": 10,
                "connection_timeout": 30.0,
                "query_timeout": 60.0,
                "enable_metrics": True
            },
            
            "subfinder": {
                "enabled": True,
                "timeout": 600,
                "retries": 3,
                "all_sources": True,
                "active": False,
                "verbose": False,
                "max_time": 10,
                "threads": 10,
                "recursive": False,
                "# sources": ["crtsh", "virustotal", "censys"],
                "# exclude_sources": ["ask"]
            },
            
            "naabu": {
                "enabled": True,
                "timeout": 900,
                "retries": 2,
                "top_ports": 1000,
                "verify": True,
                "ping": False,
                "scan_type": "syn",
                "threads": 25
            },
            
            "nmap": {
                "enabled": True,
                "timeout": 1800,
                "retries": 2,
                "scan_type": "sS",
                "top_ports": 1000,
                "timing": "T4",
                "version_detection": True,
                "os_detection": False,
                "script_scan": True,
                "aggressive": False
            },
            
            "whois": {
                "enabled": True,
                "timeout": 60,
                "retries": 3,
                "follow_referrals": True,
                "port": 43,
                "raw": False
            }
        }
        
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as file:
            yaml.dump(sample_config, file, default_flow_style=False, indent=2)
        
        self.logger.info(f"Sample configuration saved to {output_path}")

    def get_runtime_info(self) -> Dict[str, Any]:
        """
        Get runtime configuration information.
        
        Returns:
            Runtime configuration info
        """
        return {
            "config_path": self.config_path,
            "environment_overrides": len(self._environment_overrides),
            "temp_directory": self._config.temp_directory if self._config else None,
            "log_level": self._config.log_level if self._config else None,
            "tools_enabled": {
                tool: getattr(self._config, tool).enabled 
                for tool in ['subfinder', 'nmap', 'naabu', 'whois']
            } if self._config else {},
            "configuration_loaded": self._config is not None
        }

    def reload_configuration(self) -> None:
        """Reload configuration from file and environment variables."""
        self.logger.info("Reloading configuration...")
        self.load_configuration()


# Global configuration instance
_global_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get global configuration manager instance.
    
    Args:
        config_path: Path to configuration file (only used on first call)
        
    Returns:
        ConfigManager instance
    """
    global _global_config_manager
    
    if _global_config_manager is None:
        _global_config_manager = ConfigManager(config_path)
    
    return _global_config_manager


def get_config() -> ReconConfig:
    """
    Get global configuration.
    
    Returns:
        ReconConfig instance
    """
    return get_config_manager().get_config()


def get_tool_config(tool_name: str) -> ToolConfig:
    """
    Get tool-specific configuration.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Tool configuration
    """
    return get_config_manager().get_tool_config(tool_name)