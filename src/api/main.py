"""
FastAPI application for OpenEASD.

Main application entry point for the read-only REST API.
Write operations are handled through the CLI.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from src.api.routes import domains, scans, alerts, health, findings
from src.api.settings import settings
from src.utils.config import Config
from src.utils.logging import setup_logging
import os


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

# API Routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(domains.router, prefix="/api/v1/domains", tags=["domains"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
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
