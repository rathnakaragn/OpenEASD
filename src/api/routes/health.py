"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends
from src.api.schemas.common import HealthResponse
from src.data.database.duckdb_manager import DuckDBManager
from src.api.dependencies import get_db_manager

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: DuckDBManager = Depends(get_db_manager)):
    """
    Health check endpoint.

    Returns system health status, version information,
    and database connectivity status.
    """
    # Test database connectivity
    db_status = "connected"
    try:
        # Simple query to test database
        db.connection.execute("SELECT 1").fetchone()
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="healthy",
        version="2.0.0",
        database=db_status
    )
