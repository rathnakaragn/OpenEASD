#!/bin/bash

# OpenEASD FastAPI Development Server Startup Script
# Usage: ./run_dev.sh [OPTIONS]
#
# OPTIONS:
#   --host HOST          Server host (default: 0.0.0.0)
#   --port PORT          Server port (default: 8000)
#   --reload             Auto-reload on code changes (enabled by default)
#   --no-reload          Disable auto-reload
#   --workers N          Number of workers (default: 1 for dev)
#   --log-level LEVEL    Log level: critical, error, warning, info, debug (default: info)
#   --help               Show this help message

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
HOST="0.0.0.0"
PORT="8000"
RELOAD="--reload"
WORKERS="1"
LOG_LEVEL="info"
APP_MODULE="src.api.main:app"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --reload)
      RELOAD="--reload"
      shift
      ;;
    --no-reload)
      RELOAD=""
      shift
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --help)
      sed -n '2,19p' "$0" | sed 's/^# //'
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Display startup information
clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     OpenEASD FastAPI Development Server                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Configuration:${NC}"
echo "  Host:        ${YELLOW}${HOST}${NC}"
echo "  Port:        ${YELLOW}${PORT}${NC}"
echo "  Auto-reload: ${YELLOW}$([ -n "$RELOAD" ] && echo 'Enabled' || echo 'Disabled')${NC}"
echo "  Workers:     ${YELLOW}${WORKERS}${NC}"
echo "  Log Level:   ${YELLOW}${LOG_LEVEL}${NC}"
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}❌ Error: 'uv' command not found${NC}"
    echo "Please install uv first: https://docs.astral.sh/uv/"
    exit 1
fi

# Check if dependencies are installed
echo -e "${YELLOW}Checking dependencies...${NC}"
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Installing dependencies with uv sync...${NC}"
    uv sync
else
    echo -e "${GREEN}✓ Virtual environment found${NC}"
fi

echo ""
echo -e "${GREEN}Starting FastAPI server...${NC}"
echo ""
echo -e "${BLUE}API Documentation: http://${HOST}:${PORT}/api/docs${NC}"
echo -e "${BLUE}Alternative Docs:  http://${HOST}:${PORT}/api/redoc${NC}"
echo -e "${BLUE}OpenAPI Schema:    http://${HOST}:${PORT}/openapi.json${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Start the server
exec uv run uvicorn $APP_MODULE \
  --host "$HOST" \
  --port "$PORT" \
  --log-level "$LOG_LEVEL" \
  --workers "$WORKERS" \
  $RELOAD
