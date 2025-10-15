import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import Config
from .routes.auth import router as auth_router
from .routes.health import router as health_router
from .routes.roles import router as roles_router
from .routes.users import router as users_router

logging.basicConfig(
    level=Config.LOG_LEVEL,
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
    version="0.1.0",
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
app.include_router(health_router)
