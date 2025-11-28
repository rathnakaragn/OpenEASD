# OpenEASD FastAPI Startup Guide

Quick guide to starting the FastAPI development server.

## Quick Start

### macOS/Linux
```bash
./run_dev.sh
```

### Windows
```batch
run_dev.bat
```

### Cross-Platform (Python)
```bash
python run_dev.py
```

## Startup Scripts

Three startup scripts are provided for flexibility:

### 1. Bash Script (`run_dev.sh`)
- **Best for**: macOS, Linux
- **Requires**: bash, uv
- **Usage**: `./run_dev.sh [OPTIONS]`

### 2. Batch Script (`run_dev.bat`)
- **Best for**: Windows
- **Requires**: Command Prompt, uv
- **Usage**: `run_dev.bat [OPTIONS]`

### 3. Python Script (`run_dev.py`)
- **Best for**: Cross-platform compatibility
- **Requires**: Python 3.7+, uv
- **Usage**: `python run_dev.py [OPTIONS]`

## Common Options

All three scripts support the same options:

```
--host HOST          Server host (default: 0.0.0.0)
--port PORT          Server port (default: 8000)
--reload             Auto-reload on code changes (enabled by default)
--no-reload          Disable auto-reload
--workers N          Number of workers (default: 1 for dev)
--log-level LEVEL    Log level: critical, error, warning, info, debug (default: info)
--help               Show help message
```

## Usage Examples

### Run with defaults
```bash
./run_dev.sh
# or
python run_dev.py
# or
run_dev.bat
```

### Run on a specific port
```bash
./run_dev.sh --port 8001
python run_dev.py --port 8001
run_dev.bat --port 8001
```

### Run on localhost only (not exposed)
```bash
./run_dev.sh --host 127.0.0.1
python run_dev.py --host 127.0.0.1
run_dev.bat --host 127.0.0.1
```

### Run without auto-reload
```bash
./run_dev.sh --no-reload
python run_dev.py --no-reload
run_dev.bat --no-reload
```

### Run with debug logging
```bash
./run_dev.sh --log-level debug
python run_dev.py --log-level debug
run_dev.bat --log-level debug
```

### Run with multiple options
```bash
./run_dev.sh --host 127.0.0.1 --port 8001 --log-level debug
python run_dev.py --host 127.0.0.1 --port 8001 --log-level debug
run_dev.bat --host 127.0.0.1 --port 8001 --log-level debug
```

### Run with multiple workers
```bash
./run_dev.sh --workers 4
python run_dev.py --workers 4
run_dev.bat --workers 4
```

## Server URLs

After starting the server, access it at:

- **API Documentation (Swagger)**: `http://0.0.0.0:8000/api/docs`
- **Alternative Docs (ReDoc)**: `http://0.0.0.0:8000/api/redoc`
- **OpenAPI Schema**: `http://0.0.0.0:8000/openapi.json`

If running on localhost only (`--host 127.0.0.1`):
- **API Documentation**: `http://127.0.0.1:8000/api/docs`
- **Alternative Docs**: `http://127.0.0.1:8000/api/redoc`

## Log Levels Explained

- **critical**: Only critical errors
- **error**: Errors and critical messages
- **warning**: Warnings, errors, and critical messages (default for production)
- **info**: General information (default for development)
- **debug**: Detailed debug information (includes all above)

### Recommended Log Levels

- **Development**: `info` (default) or `debug` for troubleshooting
- **Testing**: `warning` for cleaner output
- **Production**: `warning` or `error`

## Troubleshooting

### Error: 'uv' command not found
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows, use:
# powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Error: Virtual environment not found
The startup scripts will automatically install dependencies using `uv sync`. This may take a minute on first run.

### Port Already in Use
```bash
# Use a different port
./run_dev.sh --port 8001
```

### Server Binding to Wrong Host
If you need to access from other machines:
```bash
# Use 0.0.0.0 (default)
./run_dev.sh --host 0.0.0.0
```

If you want local access only:
```bash
./run_dev.sh --host 127.0.0.1
```

### Too Many Worker Processes
For development, use 1 worker (default):
```bash
./run_dev.sh --workers 1
```

For production testing, use multiple:
```bash
./run_dev.sh --workers 4
```

## Environment Variables

If needed, you can set environment variables before starting:

```bash
# Linux/macOS
export ANALYSIS_ENABLED=true
export LOG_LEVEL=debug
./run_dev.sh

# Windows
set ANALYSIS_ENABLED=true
set LOG_LEVEL=debug
run_dev.bat
```

## Stopping the Server

Press `Ctrl+C` to stop the server gracefully.

## Auto-Reload Behavior

When `--reload` is enabled (default):
- The server restarts when Python files change
- Useful for development
- May cause brief downtime during reload
- Disable with `--no-reload` for stable testing

## Performance Tips

### For Development
- Use `--workers 1` (default)
- Enable `--reload` for code changes
- Use `--log-level info` for clean output

### For Testing
- Disable `--reload` with `--no-reload`
- Use `--workers 1` to simulate single-process
- Use `--log-level warning` for cleaner output

### For Load Testing
- Use `--workers 4` or more
- Disable `--reload`
- Monitor system resources

## Health Check

To verify the server is running:

```bash
# Using curl
curl http://0.0.0.0:8000/api/v1/health

# Using Python
python -c "import requests; print(requests.get('http://0.0.0.0:8000/api/v1/health').json())"
```

## API Documentation Access

After starting the server:

1. **Interactive API Docs (Swagger UI)**
   - Open: http://0.0.0.0:8000/api/docs
   - Try out endpoints directly in the browser
   - View request/response examples

2. **Alternative API Docs (ReDoc)**
   - Open: http://0.0.0.0:8000/api/redoc
   - Better for documentation reading
   - Organized by tags

3. **OpenAPI Schema**
   - Open: http://0.0.0.0:8000/openapi.json
   - Raw OpenAPI 3.0 specification
   - Use with other tools (Postman, etc.)

## Next Steps

- Read [CLAUDE.md](CLAUDE.md) for implementation details
- Check [docs/README.md](docs/README.md) for complete API documentation
- Review [docs/DESIGN.md](docs/DESIGN.md) for architecture details

---

**Last Updated**: November 26, 2025
**Status**: Production-ready
**Tested On**: macOS 12+, Linux (Ubuntu 20.04+), Windows 10+
