import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import Config
from .routes.auth import router as auth_router
from .routes.roles import router as roles_router
from .routes.users import router as users_router

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler()],
)
logging.getLogger("uvicorn").propagate = False
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up FastForge application")
    # Perform any startup tasks here
    yield
    # Shutdown
    logger.info("Shutting down FastForge application")
    # Perform any cleanup tasks here


app = FastAPI(
    title="FastForge",
    description="A lightweight FastAPI boilerplate with phone-based OTP authentication and user management. To authorize in Swagger UI, use POST /auth/login to get an OTP, then POST /auth/verify-login-otp to get a JWT. Enter 'Bearer <jwt>' in the Authorize button.",
    openapi_tags=[
        {"name": "auth", "description": "Authentication endpoints (OTP-based)"},
        {"name": "users", "description": "User management endpoints (require JWT)"},
        {"name": "health", "description": "Health check"},
    ],
)

# Rate-limiting with slowapi
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=Config.ALLOWED_HOSTS if Config.ALLOWED_HOSTS != ["*"] else ["*"],
)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(users_router)
app.include_router(auth_router)
app.include_router(roles_router)


# Input models
class HealthResponse(BaseModel):
    status: str


class LoginRequest(BaseModel):
    phone_number: str
    email: EmailStr | None = None
    password: str = None


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def get_health_status():
    """
    Basic health check endpoint.

    Returns:
        HealthResponse: A dictionary with status "ok"
    """
    return {"status": "ok"}


@app.get("/health/extended", tags=["health"])
async def get_extended_health_status():
    """
    Extended health check that verifies database and Redis connectivity.

    Returns:
        dict: A dictionary with health status and checks for database and Redis
    """
    import redis
    from sqlmodel import text

    from .database import engine

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
        redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)
        redis_client.ping()
    except Exception as e:
        health_status["checks"]["redis"] = f"error: {str(e)}"
        health_status["status"] = "unhealthy"

    return health_status
