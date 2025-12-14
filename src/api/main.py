"""
FastAPI application for OpenEASD.

Main application entry point for the full CRUD REST API.
Supports domain management, async scan execution, and security findings tracking.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import domains, scans, health, findings, jobs
from src.api.settings import settings
from src.api.dependencies import cleanup_db_manager
from src.services.exceptions import (
    DomainAlreadyExists,
    DomainNotFound,
    InvalidDomainFormat,
    InvalidScanStatus,
    InvalidUpdateOperation,
    ScanNotFound,
    ScanCannotBeDeleted,
    InvalidFilterValue,
    ToolExecutionError,
    ToolTimeoutError,
    ToolNotFoundError,
    ToolOutputParseError,
)
from src.services.findings_service import FindingNotFound, InvalidFindingStatus
from src.services.job_service import JobNotFound, JobCannotBeRetried, JobCannotBeCancelled
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

    logger.info("🚀 OpenEASD API starting up...")
    logger.info(f"🖥️  Dashboard: http://localhost:{settings.port}")
    logger.info(f"📚 API Docs:  http://localhost:{settings.port}{settings.docs_url}")
    logger.info(f"📊 Logging level: {log_level}")

    yield

    # Shutdown
    logger.info("👋 OpenEASD API shutting down...")
    cleanup_db_manager()
    logger.info("✅ Database connections closed")

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
# Standardized Error Response Helper
# =============================================================================

def create_error_response(
    status_code: int,
    detail: str,
    error_code: str
) -> JSONResponse:
    """
    Create a standardized error response.

    All API errors return a consistent format:
    {
        "detail": "Human-readable error message",
        "error_code": "MACHINE_READABLE_CODE"
    }

    Args:
        status_code: HTTP status code
        detail: Human-readable error message
        error_code: Machine-readable error code

    Returns:
        JSONResponse with standardized error format
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": detail,
            "error_code": error_code
        },
    )


# =============================================================================
# Centralized Exception Handlers
# =============================================================================

@app.exception_handler(FindingNotFound)
async def finding_not_found_handler(request: Request, exc: FindingNotFound):
    """Handle FindingNotFound exceptions with 404 response."""
    return create_error_response(
        status.HTTP_404_NOT_FOUND,
        str(exc),
        "FINDING_NOT_FOUND"
    )


@app.exception_handler(InvalidFindingStatus)
async def invalid_finding_status_handler(request: Request, exc: InvalidFindingStatus):
    """Handle InvalidFindingStatus exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "INVALID_FINDING_STATUS"
    )


@app.exception_handler(DomainNotFound)
async def domain_not_found_handler(request: Request, exc: DomainNotFound):
    """Handle DomainNotFound exceptions with 404 response."""
    return create_error_response(
        status.HTTP_404_NOT_FOUND,
        str(exc),
        "DOMAIN_NOT_FOUND"
    )


@app.exception_handler(InvalidDomainFormat)
async def invalid_domain_format_handler(request: Request, exc: InvalidDomainFormat):
    """Handle InvalidDomainFormat exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "INVALID_DOMAIN_FORMAT"
    )


@app.exception_handler(ScanNotFound)
async def scan_not_found_handler(request: Request, exc: ScanNotFound):
    """Handle ScanNotFound exceptions with 404 response."""
    return create_error_response(
        status.HTTP_404_NOT_FOUND,
        str(exc),
        "SCAN_NOT_FOUND"
    )


@app.exception_handler(DomainAlreadyExists)
async def domain_already_exists_handler(request: Request, exc: DomainAlreadyExists):
    """Handle DomainAlreadyExists exceptions with 409 Conflict response."""
    return create_error_response(
        status.HTTP_409_CONFLICT,
        str(exc),
        "DOMAIN_ALREADY_EXISTS"
    )


@app.exception_handler(InvalidUpdateOperation)
async def invalid_update_operation_handler(request: Request, exc: InvalidUpdateOperation):
    """Handle InvalidUpdateOperation exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "INVALID_UPDATE_OPERATION"
    )


@app.exception_handler(InvalidScanStatus)
async def invalid_scan_status_handler(request: Request, exc: InvalidScanStatus):
    """Handle InvalidScanStatus exceptions with 409 response."""
    return create_error_response(
        status.HTTP_409_CONFLICT,
        str(exc),
        "INVALID_SCAN_STATUS"
    )


@app.exception_handler(ScanCannotBeDeleted)
async def scan_cannot_be_deleted_handler(request: Request, exc: ScanCannotBeDeleted):
    """Handle ScanCannotBeDeleted exceptions with 409 response."""
    return create_error_response(
        status.HTTP_409_CONFLICT,
        str(exc),
        "SCAN_CANNOT_BE_DELETED"
    )


@app.exception_handler(InvalidFilterValue)
async def invalid_filter_value_handler(request: Request, exc: InvalidFilterValue):
    """Handle InvalidFilterValue exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "INVALID_FILTER_VALUE"
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle ValueError exceptions with 400 response."""
    logger.info(f"Validation error in request {request.url}: {exc}")
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "VALIDATION_ERROR"
    )


@app.exception_handler(ToolExecutionError)
async def tool_execution_error_handler(request: Request, exc: ToolExecutionError):
    """Handle ToolExecutionError exceptions with 500 response."""
    logger.error(f"Tool execution error in request {request.url}: {exc}")
    return create_error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        str(exc),
        "TOOL_EXECUTION_ERROR"
    )


@app.exception_handler(ToolTimeoutError)
async def tool_timeout_error_handler(request: Request, exc: ToolTimeoutError):
    """Handle ToolTimeoutError exceptions with 504 Gateway Timeout response."""
    logger.error(f"Tool timeout error in request {request.url}: {exc}")
    return create_error_response(
        status.HTTP_504_GATEWAY_TIMEOUT,
        str(exc),
        "TOOL_TIMEOUT_ERROR"
    )


@app.exception_handler(ToolNotFoundError)
async def tool_not_found_error_handler(request: Request, exc: ToolNotFoundError):
    """Handle ToolNotFoundError exceptions with 503 Service Unavailable response."""
    logger.error(f"Tool not found error in request {request.url}: {exc}")
    return create_error_response(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        str(exc),
        "TOOL_NOT_FOUND_ERROR"
    )


@app.exception_handler(ToolOutputParseError)
async def tool_output_parse_error_handler(request: Request, exc: ToolOutputParseError):
    """Handle ToolOutputParseError exceptions with 500 response."""
    logger.error(f"Tool output parse error in request {request.url}: {exc}")
    return create_error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        str(exc),
        "TOOL_OUTPUT_PARSE_ERROR"
    )


@app.exception_handler(JobNotFound)
async def job_not_found_handler(request: Request, exc: JobNotFound):
    """Handle JobNotFound exceptions with 404 response."""
    return create_error_response(
        status.HTTP_404_NOT_FOUND,
        str(exc),
        "JOB_NOT_FOUND"
    )


@app.exception_handler(JobCannotBeRetried)
async def job_cannot_be_retried_handler(request: Request, exc: JobCannotBeRetried):
    """Handle JobCannotBeRetried exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "JOB_CANNOT_BE_RETRIED"
    )


@app.exception_handler(JobCannotBeCancelled)
async def job_cannot_be_cancelled_handler(request: Request, exc: JobCannotBeCancelled):
    """Handle JobCannotBeCancelled exceptions with 400 response."""
    return create_error_response(
        status.HTTP_400_BAD_REQUEST,
        str(exc),
        "JOB_CANNOT_BE_CANCELLED"
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Fallback handler for unhandled exceptions.

    Logs the full error for debugging but returns a generic message
    to prevent information leakage in production.
    """
    logger.error(
        f"Unhandled exception in request {request.method} {request.url}: {exc}",
        exc_info=True
    )
    return create_error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "An internal server error occurred",
        "INTERNAL_SERVER_ERROR"
    )


# API Routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(domains.router, prefix="/api/v1/domains", tags=["domains"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"])

# --- Frontend Serving ---
# Note: Place this after API routes to ensure API has priority
# Frontend is located at src/frontend/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONTEND_DIR = os.path.join(BASE_DIR, "src", "frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")
TEMPLATES_DIR = os.path.join(FRONTEND_DIR, "templates")

if os.path.exists(STATIC_DIR):
    # Mount static files directory for CSS/JS
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if os.path.exists(TEMPLATES_DIR):
    @app.get("/", include_in_schema=False)
    async def read_index():
        """Serve the main dashboard page."""
        return FileResponse(os.path.join(TEMPLATES_DIR, "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    async def catch_all(path: str):
        """Handle client-side routing - serve index.html for non-API paths."""
        # Skip API paths to allow proper 404 responses from FastAPI
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        # Check if file exists in static directory
        static_file = os.path.join(STATIC_DIR, path)
        if os.path.exists(static_file) and os.path.isfile(static_file):
            return FileResponse(static_file)

        # Otherwise serve index.html for SPA routing
        return FileResponse(os.path.join(TEMPLATES_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        reload=settings.reload
    )
