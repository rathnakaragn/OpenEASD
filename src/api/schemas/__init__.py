"""
Pydantic schemas for request/response validation.
"""

from src.api.schemas.domain import (
    DomainCreate,
    DomainUpdate,
    DomainResponse,
    DomainListResponse
)
from src.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanResultsResponse,
    ScanListResponse
)
from src.api.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingStatisticsResponse
)
from src.api.schemas.job import (
    JobResponse,
    JobListResponse,
    JobStatisticsResponse
)
from src.api.schemas.common import (
    HealthResponse,
    ErrorResponse
)

__all__ = [
    'DomainCreate',
    'DomainUpdate',
    'DomainResponse',
    'DomainListResponse',
    'ScanCreate',
    'ScanResponse',
    'ScanResultsResponse',
    'ScanListResponse',
    'FindingResponse',
    'FindingListResponse',
    'FindingStatisticsResponse',
    'JobResponse',
    'JobListResponse',
    'JobStatisticsResponse',
    'HealthResponse',
    'ErrorResponse',
]
