"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends

from src.api.schemas.common import HealthResponse
from src.api.dependencies import get_health_service
from src.services.health_service import HealthCheckService


router = APIRouter(redirect_slashes=False)


@router.get("/health", response_model=HealthResponse)
async def health_check(service: HealthCheckService = Depends(get_health_service)):
    """
    Health check endpoint.

    Returns system health status, version information,
    and database connectivity status.
    """
    result = service.check_health()

    return HealthResponse(
        status=result['status'],
        version=result['version'],
        database=result['database']
    )
