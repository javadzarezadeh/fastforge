import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session

from .auth import (
    create_access_token,
    register_user,
    send_login_otp,
    verify_otp,
    verify_password_login,
)
from .database import get_session
from .sms_service import MockSMSService, SMSService

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


app = FastAPI(title="FastForge")

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


# Input models
class HealthResponse(BaseModel):
    status: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class RegisterRequest(BaseModel):
    phone_number: str
    password: Optional[str] = None


class OTPRequest(BaseModel):
    phone_number: str
    otp: str


class LoginRequest(BaseModel):
    phone_number: str
    password: Optional[str] = None


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "ok"}


@app.post("/auth/register")
@limiter.limit("5/minute")
async def register(
    request: Request,
    data: RegisterRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(lambda: MockSMSService()),
):
    return register_user(session, data.phone_number, data.password, sms_service)


@app.post("/auth/verify-otp")
@limiter.limit("5/minute")
async def verify_otp_endpoint(
    request: Request, data: OTPRequest, session: Session = Depends(get_session)
):
    user = verify_otp(session, data.phone_number, data.otp, None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    token = create_access_token({"sub": user.phone_number})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    data: LoginRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(lambda: MockSMSService()),
):
    if data.password:
        user = verify_password_login(session, data.phone_number, data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        token = create_access_token({"sub": user.phone_number})
        return {"access_token": token, "token_type": "bearer"}
    return send_login_otp(session, data.phone_number, sms_service)


@app.post("/auth/verify-login-otp")
@limiter.limit("5/minute")
async def verify_login_otp(
    request: Request, data: OTPRequest, session: Session = Depends(get_session)
):
    user = verify_otp(session, data.phone_number, data.otp, None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    token = create_access_token({"sub": user.phone_number})
    return {"access_token": token, "token_type": "bearer"}
