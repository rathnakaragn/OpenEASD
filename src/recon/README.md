# OpenEASD Recon Layer

The Recon Layer (Layer 3) is responsible for security tool execution, data collection, output parsing, and tool orchestration in the OpenEASD 6-layer architecture.

## Architecture Overview

```
src/recon/
├── interfaces/           # Abstract interfaces
│   ├── tool.py          # ReconTool base class
│   └── __init__.py      
├── modules/             # Security tool implementations
│   ├── subfinder/       # Subdomain discovery
│   ├── nmap/           # Service detection  
│   ├── naabu/          # Port scanning
│   ├── whois/          # Domain intelligence
│   └── __init__.py
├── parsers/            # Output parsers
│   ├── subfinder_parser.py
│   ├── nmap_parser.py
│   ├── naabu_parser.py
│   ├── whois_parser.py
│   └── __init__.py
├── collectors/         # Data collection
│   ├── data_collector.py
│   └── __init__.py
├── orchestrators/      # Tool coordination
│   ├── recon_orchestrator.py
│   └── __init__.py
├── config.py          # Configuration management
└── __init__.py
```

## Features

### 🛠️ Security Tool Integration
- **Subfinder**: Subdomain discovery with passive enumeration
- **Nmap**: Service detection and port scanning with XML parsing
- **Naabu**: High-speed port scanning with JSON output
- **WHOIS**: Domain intelligence and registration analysis

### 🎼 Orchestration Engine
- Multi-tool workflow coordination
- Parallel and sequential execution modes
- Dependency management between phases
- Progress tracking and status reporting
- Error handling and recovery
- Rate limiting and throttling

### 📊 Data Collection
- Comprehensive result storage
- Database integration with DuckDB
- Asset inventory management
- Scan progress tracking
- Performance metrics collection
- Raw output preservation

### 🔧 Enhanced Parsing
- Tool-specific output parsers
- Standardized data formats
- Security risk assessment
- Asset categorization
- Vulnerability detection
- Intelligence extraction

### ⚙️ Configuration Management
- YAML/JSON configuration files
- Environment variable overrides
- Tool-specific settings
- Workflow customization
- Validation and defaults

## Quick Start

### 1. Basic Usage

```python
import asyncio
from src.recon.orchestrators.recon_orchestrator import ReconOrchestrator
from src.recon.collectors.data_collector import DataCollector
from src.db.database.duckdb_manager import DuckDBManager

async def run_recon():
    # Initialize components
    database_manager = DuckDBManager("data/openeasd.db")
    await database_manager.initialize()
    
    data_collector = DataCollector(database_manager)
    orchestrator = ReconOrchestrator(database_manager, data_collector)
    
    # Execute reconnaissance
    results = await orchestrator.execute_reconnaissance(
        targets=["example.com"],
        workflow_config={
            "tools": {
                "subfinder": {"all_sources": True},
                "naabu": {"top_ports": 1000},
                "nmap": {"version_detection": True},
                "whois": {"follow_referrals": True}
            }
        }
    )
    
    print(f"Assets discovered: {results['summary_statistics']['total_assets']}")

# Run the reconnaissance
asyncio.run(run_recon())
```

### 2. Individual Tool Usage

```python
import asyncio
from src.recon.modules.subfinder.runner import SubfinderRunner

async def run_subfinder():
    tool = SubfinderRunner()
    
    if tool.validate_installation():
        result = await tool.execute("example.com", {
            "all_sources": True,
            "timeout": 300
        })
        
        print(f"Status: {result.status}")
        print(f"Subdomains found: {len(result.assets_discovered)}")
        
        for asset in result.assets_discovered:
            print(f"  - {asset['subdomain']}")

asyncio.run(run_subfinder())
```

### 3. Configuration

Create a `config/recon_config.yaml` file:

```yaml
# Global Settings
log_level: INFO
temp_directory: /tmp/openeasd

# Workflow Configuration
workflow:
  max_concurrent_tools: 3
  enable_rate_limiting: true
  default_timeout: 1800

# Tool Configurations
subfinder:
  enabled: true
  timeout: 600
  all_sources: true
  threads: 10

naabu:
  enabled: true
  timeout: 900
  top_ports: 1000
  verify: true

nmap:
  enabled: true
  timeout: 1800
  version_detection: true
  script_scan: true

whois:
  enabled: true
  timeout: 60
  follow_referrals: true
```

## Tool Implementations

### Subfinder - Subdomain Discovery

**Features:**
- Passive subdomain enumeration
- Multiple data source integration
- JSON output parsing
- Source attribution
- Confidence scoring

**Configuration Options:**
- `all_sources`: Use all available sources
- `active`: Enable active enumeration
- `timeout`: Execution timeout
- `sources`: Custom source list
- `exclude_sources`: Sources to exclude
- `recursive`: Recursive enumeration

### Nmap - Service Detection

**Features:**
- Service version detection
- OS fingerprinting
- NSE script execution
- XML output parsing
- Security analysis

**Configuration Options:**
- `scan_type`: Scan type (sS, sT, etc.)
- `top_ports`: Number of top ports
- `version_detection`: Enable version detection
- `script_scan`: Run NSE scripts
- `timing`: Timing template (T1-T5)

### Naabu - Port Scanning

**Features:**
- High-speed SYN scanning
- Host discovery
- JSON output
- Port categorization
- Service inference

**Configuration Options:**
- `top_ports`: Number of top ports
- `verify`: Verify open ports
- `scan_type`: syn or connect
- `threads`: Concurrent threads

### WHOIS - Domain Intelligence

**Features:**
- Domain registration info
- Registrar analysis
- DNS information
- Expiration tracking
- Security posture assessment

**Configuration Options:**
- `follow_referrals`: Follow WHOIS referrals
- `server`: Custom WHOIS server
- `timeout`: Query timeout

## Orchestration Workflows

### Default Workflow Phases

1. **Domain Intelligence** - WHOIS analysis
2. **Subdomain Discovery** - Subfinder enumeration
3. **Port Scanning** - Naabu scanning on discovered assets
4. **Service Detection** - Nmap analysis of open ports

### Custom Workflows

```python
workflow_config = {
    "phases": [
        {
            "phase": "subdomain_discovery",
            "tools": ["subfinder"],
            "parallel": True,
            "dependencies": []
        },
        {
            "phase": "port_scanning", 
            "tools": ["naabu"],
            "parallel": True,
            "dependencies": ["subdomain_discovery"]
        }
    ]
}
```

## Data Collection & Storage

### Asset Inventory

All discovered assets are stored in a standardized format:

```python
{
    "domain": "example.com",
    "subdomain": "api.example.com",
    "ip_address": "1.2.3.4",
    "port": 443,
    "protocol": "tcp",
    "service": "https",
    "service_version": "nginx/1.18.0",
    "confidence_score": 95,
    "scan_source": "nmap",
    "tags": ["web", "ssl"],
    "metadata": {...}
}
```

### Progress Tracking

Scan progress is tracked per tool and phase:

```python
{
    "scan_id": "uuid",
    "domain": "example.com", 
    "phase": "service_detection",
    "tool": "nmap",
    "status": "completed",
    "progress_percentage": 100,
    "results_count": 15,
    "duration_seconds": 45.2
}
```

## Advanced Features

### Custom Parsers

Extend parsing capabilities:

```python
from src.recon.parsers.base_parser import BaseParser

class CustomParser(BaseParser):
    def parse(self, raw_output: str, target: str) -> Dict[str, Any]:
        # Custom parsing logic
        return parsed_data
```

### Progress Callbacks

Monitor scan progress:

```python
def progress_callback(progress_info):
    event_type = progress_info["event_type"]
    if event_type == "phase_completed":
        print(f"Completed: {progress_info['data']['phase']}")

orchestrator.add_progress_callback(progress_callback)
```

### Rate Limiting

Configure tool rate limits:

```yaml
workflow:
  enable_rate_limiting: true
  
# Per-tool rate limits (requests per second)
rate_limits:
  subfinder: 5
  naabu: 10
  nmap: 2
```

## Error Handling

The Recon Layer provides robust error handling:

- **Tool Installation Validation**: Automatic tool availability checks
- **Execution Timeouts**: Configurable timeouts per tool
- **Retry Logic**: Automatic retries with exponential backoff
- **Graceful Degradation**: Continue operation with partial failures
- **Error Reporting**: Detailed error information and logging

## Performance Optimization

### Concurrency Control

```python
orchestrator = ReconOrchestrator(
    max_concurrent_tools=5,      # Limit concurrent executions
    enable_rate_limiting=True,   # Enable rate limiting
    default_timeout=1800         # 30-minute timeout
)
```

### Resource Management

- Automatic cleanup of temporary files
- Memory-efficient output streaming
- Database connection pooling
- Async/await throughout for non-blocking I/O

## Integration Examples

### With Database Layer

```python
from src.db.database.duckdb_manager import DuckDBManager

# Initialize database
db_manager = DuckDBManager("data/recon.db")
await db_manager.initialize()

# Use with orchestrator
orchestrator = ReconOrchestrator(database_manager=db_manager)
```

### With API Layer

```python
from fastapi import FastAPI
from src.recon.orchestrators.recon_orchestrator import ReconOrchestrator

app = FastAPI()
orchestrator = ReconOrchestrator()

@app.post("/scan")
async def start_scan(targets: List[str]):
    results = await orchestrator.execute_reconnaissance(targets)
    return results
```

## Troubleshooting

### Common Issues

1. **Tool Not Found**
   - Ensure tools are installed and in PATH
   - Check `executable_path` configuration
   - Validate with `tool.validate_installation()`

2. **Timeout Errors**
   - Increase timeout values in configuration
   - Check network connectivity
   - Verify target accessibility

3. **Permission Errors**
   - Some nmap scans require root privileges
   - Check file system permissions
   - Verify database write access

4. **Memory Issues**
   - Reduce concurrent tool limit
   - Disable raw output storage for large scans
   - Use smaller target batches

### Debug Logging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or via configuration
log_level: DEBUG
```

## Best Practices

1. **Security**
   - Run with minimal required privileges
   - Sanitize all inputs
   - Validate tool outputs
   - Use secure temporary directories

2. **Performance**
   - Tune concurrency limits for your environment
   - Use appropriate timeouts
   - Monitor resource usage
   - Implement rate limiting for external targets

3. **Reliability**
   - Enable retries for transient failures
   - Implement proper error handling
   - Use database transactions
   - Regular cleanup of old data

4. **Monitoring**
   - Use progress callbacks for long-running scans
   - Monitor tool execution metrics
   - Track error rates
   - Log significant events

## Contributing

When adding new tools:

1. Extend `ReconTool` base class
2. Implement required abstract methods
3. Add comprehensive output parser
4. Include configuration options
5. Add validation and error handling
6. Write unit tests
7. Update documentation

## License

This implementation is part of the OpenEASD project by Cybersecify.