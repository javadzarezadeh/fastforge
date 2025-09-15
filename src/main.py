import logging
import os

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session

from .auth import (
    create_access_token,
    send_login_otp,
    verify_otp,
)
from .database import get_session
from .routes.users import router as users_router
from .sms_service import MockSMSService, SMSService

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler()],
)
logging.getLogger("uvicorn").propagate = False
logger = logging.getLogger(__name__)


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

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(users_router)


# Input models
class HealthResponse(BaseModel):
    status: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class OTPRequest(BaseModel):
    phone_number: str


class VerifyOTPRequest(BaseModel):
    phone_number: str
    otp: str
    email: EmailStr | None = None


class LoginRequest(BaseModel):
    phone_number: str
    email: EmailStr | None = None
    password: str = None


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    return {"status": "ok"}


@app.post("/auth/request-otp", tags=["auth"])
@limiter.limit("5/minute")
async def request_otp(
    request: Request,
    data: OTPRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(lambda: MockSMSService()),
):
    return send_login_otp(session, data.phone_number, sms_service)


@app.post("/auth/login", tags=["auth"])
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    phone_number = form_data.username
    password_or_otp = form_data.password
    # No password/OTP: send OTP
    if not password_or_otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP required; use POST /auth/request-otp first",
        )
    # Verify OTP and create user if needed
    user = verify_otp(session, phone_number, password_or_otp)
    access_token = create_access_token(data={"sub": user.phone_number})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/verify-login-otp", response_model=TokenResponse, tags=["auth"])
@limiter.limit("5/minute")
async def verify_login_otp(
    request: Request, data: VerifyOTPRequest, session: Session = Depends(get_session)
):
    user = verify_otp(session, data.phone_number, data.otp, data.email)
    access_token = create_access_token(data={"sub": user.phone_number})
    return {"access_token": access_token, "token_type": "bearer"}
