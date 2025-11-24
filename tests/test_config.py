import json
import os
from pathlib import Path
import pytest
from src.utils.config import Config

@pytest.fixture
def temp_config_files(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    # Create dummy recon_config.yaml
    recon_config_content = """
    database:
      database_path: data/openeasd.db
      max_connections: 10
    subfinder:
      timeout: 600
    """
    (config_dir / "recon_config.yaml").write_text(recon_config_content)

    # Create dummy config.json for user overrides
    user_config_content = {
        "database": {
            "max_connections": 20
        },
        "new_user_setting": "user_value"
    }
    (config_dir / "config.json").write_text(json.dumps(user_config_content))

    return config_dir / "config.json", config_dir / "recon_config.yaml"

def test_load_default_config(temp_config_files):
    _, recon_config_path = temp_config_files
    # Test loading only the default YAML
    config = Config(recon_config_path=recon_config_path, config_path="nonexistent.json")
    assert config.get('database.database_path') == 'data/openeasd.db'
    assert config.get('database.max_connections') == 10
    assert config.get('subfinder.timeout') == 600

def test_load_with_user_overrides(temp_config_files):
    config_path, recon_config_path = temp_config_files
    config = Config(config_path=config_path, recon_config_path=recon_config_path)
    
    # Assert that user setting overrides default
    assert config.get('database.max_connections') == 20
    
    # Assert that default values are still available
    assert config.get('database.database_path') == 'data/openeasd.db'
    assert config.get('subfinder.timeout') == 600
    
    # Assert that a new setting from user config is present
    assert config.get('new_user_setting') == 'user_value'

def test_get_with_default_value():
    config = Config(config_path="nonexistent.json", recon_config_path="nonexistent.yaml")
    assert config.get('nonexistent.key', 'default_value') == 'default_value'

def test_set_value(temp_config_files):
    config_path, recon_config_path = temp_config_files
    config = Config(config_path=config_path, recon_config_path=recon_config_path)

    # Set a new value
    config.set('new.nested.setting', 'new_value')
    assert config.get('new.nested.setting') == 'new_value'

    # Verify it's saved to the user config file
    with open(config_path, 'r') as f:
        user_config = json.load(f)
    assert user_config['new']['nested']['setting'] == 'new_value'
