"""
FastAPI application for OpenEASD.

Main application entry point for the REST API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routes import domains, scans, alerts, health

# Create FastAPI application
app = FastAPI(
    title="OpenEASD API",
    description="Automated External Attack Surface Detection API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    health.router,
    prefix="/api/v1",
    tags=["health"]
)

app.include_router(
    domains.router,
    prefix="/api/v1/domains",
    tags=["domains"]
)

app.include_router(
    scans.router,
    prefix="/api/v1/scans",
    tags=["scans"]
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["alerts"]
)


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    print("🚀 OpenEASD API starting up...")
    print("📚 API Documentation: http://localhost:8000/api/docs")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    print("👋 OpenEASD API shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
