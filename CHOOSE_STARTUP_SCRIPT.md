# Which Startup Script Should I Use?

Quick decision guide for choosing the right startup script for your environment.

## Decision Tree

```
Do you use Windows?
├─ YES → Use run_dev.bat
│        Or python run_dev.py
│
└─ NO (macOS/Linux)
   ├─ Prefer bash?
   │  └─ YES → Use ./run_dev.sh ⭐ Recommended
   │
   └─ Want cross-platform?
      └─ YES → Use python run_dev.py
```

## Quick Recommendation

| OS | Recommended | Alternative |
|---|---|---|
| **macOS** | `./run_dev.sh` ⭐ | `python run_dev.py` |
| **Linux** | `./run_dev.sh` ⭐ | `python run_dev.py` |
| **Windows** | `run_dev.bat` or `python run_dev.py` | N/A |

## Detailed Comparison

### run_dev.sh (Bash) ⭐ RECOMMENDED FOR UNIX
- **Best For**: macOS, Linux
- **Pros**:
  - Lightweight and fast
  - Simple shell script
  - Native to Unix systems
  - Easy to understand and modify
  - Minimal dependencies
- **Cons**:
  - Won't work on Windows (use WSL or Python version)
- **Command**: `./run_dev.sh [OPTIONS]`

### run_dev.bat (Batch) - FOR WINDOWS
- **Best For**: Windows CMD or PowerShell
- **Pros**:
  - Native Windows batch script
  - No Python needed
  - Integrated with Windows environment
  - Can be scheduled with Task Scheduler
- **Cons**:
  - Only works on Windows
  - Less powerful than other options
  - Limited color support in old Windows versions
- **Command**: `run_dev.bat [OPTIONS]`

### run_dev.py (Python) - CROSS-PLATFORM ✓
- **Best For**: Teams with mixed environments
- **Pros**:
  - Works on Windows, macOS, Linux
  - Rich features and colored output
  - Better error messages
  - Easier to extend and modify
  - Professional-grade implementation
- **Cons**:
  - Requires Python (but you have it)
  - Slightly slower startup than bash
- **Command**: `python run_dev.py [OPTIONS]`

## Scenario-Based Recommendations

### 👨‍💻 Solo Developer on macOS/Linux
**→ Use `./run_dev.sh`**
```bash
./run_dev.sh
```

### 👨‍💻 Solo Developer on Windows
**→ Use `run_dev.bat` or `python run_dev.py`**
```batch
run_dev.bat
```

### 👥 Team with Multiple Developers
**→ Use `python run_dev.py`**
```bash
python run_dev.py  # Works everywhere
```

### 🤖 CI/CD Pipeline
**→ Use `python run_dev.py`**
```bash
python run_dev.py --no-reload --port $PORT
```

### 📚 Docker Container
**→ Use `python run_dev.py`**
```dockerfile
CMD ["python", "run_dev.py", "--host", "0.0.0.0"]
```

### 🏢 Production Server
**→ Use `python run_dev.py` with gunicorn or systemd**
```bash
# Option 1: With gunicorn
gunicorn src.api.main:app --workers 4 --bind 0.0.0.0:8000

# Option 2: With systemd service
systemctl start openeasd-api
```

## Platform-Specific Instructions

### macOS
```bash
# Make script executable (first time only)
chmod +x run_dev.sh

# Run it
./run_dev.sh

# Or use Python version
python run_dev.py
```

### Linux (Ubuntu/Debian)
```bash
# Make script executable (first time only)
chmod +x run_dev.sh

# Run it
./run_dev.sh

# Or use Python version
python3 run_dev.py
```

### Windows (Command Prompt)
```batch
# Run batch script
run_dev.bat

# Or use Python
python run_dev.py
```

### Windows (PowerShell)
```powershell
# Run batch script
.\run_dev.bat

# Or use Python
python .\run_dev.py
```

### Windows Subsystem for Linux (WSL)
```bash
# Use bash version (available in WSL)
./run_dev.sh

# Or use Python
python run_dev.py
```

## When to Switch Scripts

### Switch FROM `run_dev.sh` TO `run_dev.py` if:
- You need to run on Windows
- You want better error messages
- You need more advanced features
- You're working in a mixed team

### Switch FROM `run_dev.bat` TO `run_dev.py` if:
- You want colored output
- You need better cross-platform compatibility
- You want more configuration options

### Switch FROM `run_dev.py` TO `run_dev.sh` if:
- You want fastest startup time
- You're on Unix and prefer minimal dependencies
- You want simplicity

## Feature Comparison Table

| Feature | run_dev.sh | run_dev.bat | run_dev.py |
|---------|-----------|-----------|-----------|
| macOS | ✅ | ❌ | ✅ |
| Linux | ✅ | ❌ | ✅ |
| Windows | ❌ | ✅ | ✅ |
| WSL | ✅ | ⚠️ | ✅ |
| Colored Output | ✅ | ⚠️ | ✅ |
| Error Messages | ⚠️ | ⚠️ | ✅ |
| Help Message | ✅ | ✅ | ✅ |
| Configuration Options | ✅ | ✅ | ✅ |
| Startup Speed | ⚡ Fast | ⚡ Fast | ⚡ Fast |
| Easy to Modify | ✅ | ⚠️ | ✅ |
| Learning Curve | Easy | Medium | Easy |

## Getting Help

All scripts support `--help`:

```bash
./run_dev.sh --help
python run_dev.py --help
run_dev.bat --help
```

## Troubleshooting by Script

### run_dev.sh Issues
- **"Permission denied"**: Run `chmod +x run_dev.sh`
- **"command not found"**: Make sure you're in the right directory
- **"uv: not found"**: Install uv from https://docs.astral.sh/uv/

### run_dev.bat Issues
- **"'run_dev.bat' is not recognized"**: Make sure you're in the right directory
- **"uv is not recognized"**: Install uv and add to PATH

### run_dev.py Issues
- **"ModuleNotFoundError"**: Run `pip install -r requirements.txt` first
- **"uv not found"**: Install uv from https://docs.astral.sh/uv/

## Performance Comparison

All three scripts have similar performance once the server starts:
- Server startup time: ~1-2 seconds
- First request time: ~100-200ms
- Memory usage: ~50-100MB

The script choice won't significantly impact server performance.

## Conclusion

| If you want... | Use... |
|---|---|
| **Simplest native solution** | `./run_dev.sh` (macOS/Linux) |
| **Windows native** | `run_dev.bat` |
| **Maximum compatibility** | `python run_dev.py` ⭐ |
| **Team collaboration** | `python run_dev.py` ⭐ |
| **Professional production** | `python run_dev.py` ⭐ |

---

**Recommendation**: For most users, especially teams, use `python run_dev.py`. It's simple, powerful, and works everywhere.

**Last Updated**: November 26, 2025
