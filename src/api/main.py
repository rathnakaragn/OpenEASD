"""
FastAPI application for OpenEASD (Read-Only).

Main application entry point for the REST API and web frontend.
This API is read-only for security. All write operations must be performed via CLI.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from src.api.routes import domains, scans, alerts, health
import os

# Create FastAPI application
app = FastAPI(
    title="OpenEASD API (Read-Only)",
    description="""
    Read-Only API for monitoring External Attack Surface Detection.

    **Security Model:**
    - API: Read-only access (GET requests only)
    - CLI: Full access for all operations (add, update, delete, scan)

    **For write operations, use the CLI:**
    - Domain management: `openeasd domain add/update/remove`
    - Scan execution: `openeasd scan domain <domain>`
    - Batch scanning: `openeasd scan`
    """,
    version="2.0.0-readonly",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(domains.router, prefix="/api/v1/domains", tags=["domains"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])

# --- Frontend Serving ---
# Note: Place this after API routes to ensure API has priority
FRONTEND_DIR = "frontend"

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
        file_path = os.path.join(FRONTEND_DIR, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
             return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

# --- Lifecycle Events ---
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    print("🚀 OpenEASD API & Frontend starting up...")
    print("🖥️  Dashboard available at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/api/docs")
    print("⚠️  Write operations disabled - use CLI for operations")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    print("👋 OpenEASD API & Frontend shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
