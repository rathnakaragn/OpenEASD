"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func

from src.api.schemas.common import HealthResponse
from src.data.database.sqlmodel_manager import SQLModelManager
from src.data.models import Domain
from src.api.dependencies import get_db_manager
from src.api.settings import settings

router = APIRouter(redirect_slashes=False)


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
        with Session(db.engine) as session:
            session.exec(select(func.count(Domain.domain))).one()
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="healthy",
        version=settings.version,
        database=db_status
    )
