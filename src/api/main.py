"""
FastAPI application for OpenEASD.

Main application entry point for the read-only REST API.
Write operations are handled through the CLI.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import domains, scans, health, findings
from src.api.settings import settings
from src.services.exceptions import (
    DomainNotFound,
    InvalidDomainFormat,
    ScanNotFound,
)
from src.services.findings_service import FindingNotFound, InvalidFindingStatus
from src.utils.config import Config
from src.utils.logging import setup_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    # Startup
    # Initialize logging from config
    config = Config()
    log_level = config.get('log_level', 'INFO')
    setup_logging(log_level)

    print("🚀 OpenEASD API starting up...")
    print(f"🖥️  Dashboard available at: http://{settings.host}:{settings.port}")
    print(f"📚 API Documentation: http://{settings.host}:{settings.port}{settings.docs_url}")
    print("📖 Read-only API - write operations via CLI")
    print(f"📊 Logging level: {log_level}")

    yield

    # Shutdown
    print("👋 OpenEASD API shutting down...")

# Create FastAPI application with settings from config
app = FastAPI(
    title=settings.title,
    description=settings.description,
    version=settings.version,
    docs_url=settings.docs_url,
    redoc_url=settings.redoc_url,
    openapi_url=settings.openapi_url,
    lifespan=lifespan
)

# Configure CORS from settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


# =============================================================================
# Centralized Exception Handlers
# =============================================================================

@app.exception_handler(FindingNotFound)
async def finding_not_found_handler(request: Request, exc: FindingNotFound):
    """Handle FindingNotFound exceptions with 404 response."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidFindingStatus)
async def invalid_finding_status_handler(request: Request, exc: InvalidFindingStatus):
    """Handle InvalidFindingStatus exceptions with 400 response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(DomainNotFound)
async def domain_not_found_handler(request: Request, exc: DomainNotFound):
    """Handle DomainNotFound exceptions with 404 response."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidDomainFormat)
async def invalid_domain_format_handler(request: Request, exc: InvalidDomainFormat):
    """Handle InvalidDomainFormat exceptions with 400 response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(ScanNotFound)
async def scan_not_found_handler(request: Request, exc: ScanNotFound):
    """Handle ScanNotFound exceptions with 404 response."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle ValueError exceptions with 400 response."""
    logger.warning(f"ValueError in request {request.url}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


# API Routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(domains.router, prefix="/api/v1/domains", tags=["domains"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])

# --- Frontend Serving ---
# Note: Place this after API routes to ensure API has priority
FRONTEND_DIR = settings.frontend_dir

if os.path.exists(FRONTEND_DIR):
    # Mount static files directory
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def read_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    async def catch_all(path: str):
        # This catch-all is for client-side routing.
        # It serves index.html for any path not caught by API or static files.
        # BUT: Skip API paths to allow proper 404 responses from FastAPI
        if path.startswith("api/"):
            # Let FastAPI handle API routes - will return 404 if not found
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not Found")

        file_path = os.path.join(FRONTEND_DIR, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
             return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        reload=settings.reload
    )
