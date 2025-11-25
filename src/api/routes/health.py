"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends
from src.api.schemas.common import HealthResponse
from src.data.database.sqlmodel_manager import SQLModelManager
from src.api.dependencies import get_db_manager

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: SQLModelManager = Depends(get_db_manager)):
    """
    Health check endpoint.

    Returns system health status, version information,
    and database connectivity status.
    """
    # Test database connectivity
    db_status = "connected"
    try:
        # Simple query to test database using SQLModel
        from sqlmodel import Session, select, func
        from src.data.models import Domain
        with Session(db.engine) as session:
            session.exec(select(func.count(Domain.domain))).one()
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="healthy",
        version="2.0.0",
        database=db_status
    )
