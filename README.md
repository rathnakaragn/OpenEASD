# OpenEASD - External Attack Surface Detection CLI

**Simple command-line tool for subdomain enumeration and port scanning**

## Overview
OpenEASD is a lightweight CLI tool that automates subdomain discovery and port scanning. Perfect for security researchers, penetration testers, and DevOps teams.

## Features
- 🔍 **Subdomain Discovery** - Powered by Subfinder
- 🔓 **Port Scanning** - Fast scanning with Naabu
- 💾 **Scan History** - Optional DuckDB storage
- 📊 **Multiple Output Formats** - Table, JSON, CSV
- ⚡ **Zero Dependencies** - Uses only Python standard library

## Installation

### 1. Install Security Tools
```bash
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### 2. Clone Repository
```bash
git clone https://github.com/yourusername/OpenEASD.git
cd OpenEASD
```

### 3. Install Dependencies (Optional)
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
# Scan a domain
python openeasd.py scan example.com

# Scan with custom port count
python openeasd.py scan example.com --ports 2000

# Save results to database
python openeasd.py scan example.com --save
```

### Output Formats
```bash
# Table format (default)
python openeasd.py scan example.com --output table

# JSON format
python openeasd.py scan example.com --output json

# CSV format
python openeasd.py scan example.com --output csv
```

### Scan History
```bash
# View scan history
python openeasd.py history

# View specific scan results
python openeasd.py results <scan-id>
```

### Advanced Options
```bash
# Custom timeout
python openeasd.py scan example.com --timeout 600

# Custom database path
python openeasd.py scan example.com --save --db-path ~/my-scans.db
```

## Examples

### Example 1: Quick Scan
```bash
$ python openeasd.py scan example.com

[*] Starting scan for: example.com
[*] Top ports to scan: 1000

[1/2] Discovering subdomains...
[+] Found 15 subdomains

[2/2] Scanning ports...
[+] Found 8 open ports

================================================================================
Scan Results: example.com
================================================================================
Total Subdomains: 15
Total Ports: 8

--------------------------------------------------------------------------------
Discovered Subdomains:
--------------------------------------------------------------------------------
  • www.example.com
  • api.example.com
  • mail.example.com
  ...

--------------------------------------------------------------------------------
Open Ports:
--------------------------------------------------------------------------------
  example.com:
    • Port 80/tcp (93.184.216.34)
    • Port 443/tcp (93.184.216.34)
```

### Example 2: JSON Output
```bash
$ python openeasd.py scan example.com --output json --save

{
  "type": "scan_results",
  "scan_id": "a1b2c3d4-5e6f-7g8h-9i0j-k1l2m3n4o5p6",
  "domain": "example.com",
  "timestamp": "2025-01-20T10:30:00.000000",
  "subdomains": [
    "www.example.com",
    "api.example.com"
  ],
  "ports": [
    {
      "subdomain": "example.com",
      "port": 80,
      "protocol": "tcp",
      "ip": "93.184.216.34"
    }
  ],
  "summary": {
    "total_subdomains": 15,
    "total_ports": 8
  }
}
```

## Architecture

```
┌─────────────────────────────┐
│   CLI (argparse)            │  ← Command-line interface
├─────────────────────────────┤
│   Commands                  │  ← scan, history, results
│   - Subfinder integration   │
│   - Naabu integration       │
├─────────────────────────────┤
│   Storage (SQLite)          │  ← Optional scan history
└─────────────────────────────┘
```

## Project Structure
```
OpenEASD/
├── openeasd.py              # CLI entry point
├── src/
│   ├── cli/
│   │   ├── main.py         # CLI parser
│   │   ├── commands.py     # Command implementations
│   │   └── formatters.py   # Output formatters
│   ├── storage/
│   │   └── sqlite_storage.py  # SQLite storage
│   └── recon/
│       └── modules/        # Tool modules (kept for reference)
├── requirements.txt        # Minimal dependencies
└── README.md              # This file
```

## Configuration

Optional `.env` file:
```bash
# Tool paths (if not in PATH)
SUBFINDER_PATH=/usr/local/bin/subfinder
NAABU_PATH=/usr/local/bin/naabu

# Defaults
MAX_PORTS_TO_SCAN=1000
SCAN_TIMEOUT_SECONDS=300
DB_PATH=~/.openeasd/scans.db
```

## Command Reference

### `scan` - Run a scan
```
python openeasd.py scan <domain> [options]

Options:
  --ports N          Number of top ports to scan (default: 1000)
  --timeout N        Scan timeout in seconds (default: 300)
  --output FORMAT    Output format: table, json, csv (default: table)
  --save             Save results to database
  --db-path PATH     Database file path (default: ~/.openeasd/scans.db)
```

### `history` - View scan history
```
python openeasd.py history [options]

Options:
  --limit N          Number of scans to show (default: 10)
  --output FORMAT    Output format: table, json (default: table)
  --db-path PATH     Database file path
```

### `results` - View scan results
```
python openeasd.py results <scan-id> [options]

Options:
  --output FORMAT    Output format: table, json, csv (default: table)
  --db-path PATH     Database file path
```

## Requirements

- **Python**: 3.8+
- **Subfinder**: For subdomain enumeration
- **Naabu**: For port scanning
- **SQLite3**: Built into Python (for scan history)

## Why CLI Instead of API?

This tool is designed for **local, manual security testing**. Benefits:

✅ **Simple** - No HTTP server, no cloud database, no complexity
✅ **Fast** - Direct tool execution, no API overhead
✅ **Portable** - Single Python script, runs anywhere
✅ **Offline** - Works without internet (after tools are installed)
✅ **Private** - All data stays on your machine

## Troubleshooting

**Subfinder not found**:
```bash
# Make sure it's in PATH
which subfinder

# Or specify full path in .env
SUBFINDER_PATH=/path/to/subfinder
```

**Naabu not found**:
```bash
# Make sure it's in PATH
which naabu

# Or specify full path in .env
NAABU_PATH=/path/to/naabu
```

**Permission denied on naabu**:
```bash
# Naabu requires privileges for SYN scanning
sudo python openeasd.py scan example.com
```

## License
Proprietary - Cybersecify

---

**Built by**: Cybersecify | **Author**: Rathnakara G N

**Simple. Fast. Effective.**
