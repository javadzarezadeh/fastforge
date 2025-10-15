from datetime import datetime, timezone

import redis
from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlmodel import text

from ..config import Config
from ..database import engine

router = APIRouter(prefix="/health", tags=["health"])


# Response models using proper Pydantic schemas
class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status of the application")


class ExtendedHealthResponse(BaseModel):
    status: str
    checks: dict
    timestamp: str


@router.get("", response_model=HealthResponse, tags=["health"])
async def get_health_status():
    """
    Basic health check endpoint.

    Returns:
        HealthResponse: A dictionary with status "ok"
    """
    return {"status": "ok"}


@router.get("/extended", response_model=ExtendedHealthResponse, tags=["health"])
async def get_extended_health_status():
    """
    Extended health check that verifies database and Redis connectivity.

    Returns:
        ExtendedHealthResponse: A dictionary with health status and checks for database and Redis
    """
    health_status = {
        "status": "healthy",
        "checks": {"database": "ok", "redis": "ok"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Check database connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        health_status["checks"]["database"] = f"error: {str(e)}"
        health_status["status"] = "unhealthy"

    # Check Redis connectivity
    try:
        redis_client = redis.Redis.from_url(
            Config.get_redis_url(), decode_responses=True
        )
        redis_client.ping()
    except Exception as e:
        health_status["checks"]["redis"] = f"error: {str(e)}"
        health_status["status"] = "unhealthy"

    return health_status
