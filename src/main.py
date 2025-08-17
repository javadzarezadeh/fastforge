import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlmodel import Session, SQLModel

from .auth import (
    create_access_token,
    register_user,
    send_login_otp,
    verify_otp,
    verify_password_login,
)
from .database import get_session
from .sms_service import MockSMSService, SMSService

app = FastAPI(title="FastForge")

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Input models
class RegisterRequest(BaseModel):
    phone_number: str
    password: Optional[str] = None


class OTPRequest(BaseModel):
    phone_number: str
    otp: str


class LoginRequest(BaseModel):
    phone_number: str
    password: Optional[str] = None


@app.on_event("startup")
async def on_startup():
    SQLModel.metadata.create_all(bind=next(get_session()).bind)


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/auth/register")
async def register(
    request: RegisterRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(lambda: MockSMSService()),
):
    return register_user(session, request.phone_number, request.password, sms_service)


@app.post("/auth/verify-otp")
async def verify_otp_endpoint(
    request: OTPRequest, session: Session = Depends(get_session)
):
    user = verify_otp(session, request.phone_number, request.otp, None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    token = create_access_token({"sub": user.phone_number})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/login")
async def login(
    request: LoginRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(lambda: MockSMSService()),
):
    if request.password:
        user = verify_password_login(session, request.phone_number, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        token = create_access_token({"sub": user.phone_number})
        return {"access_token": token, "token_type": "bearer"}
    return send_login_otp(session, request.phone_number, sms_service)


@app.post("/auth/verify-login-otp")
async def verify_login_otp(
    request: OTPRequest, session: Session = Depends(get_session)
):
    user = verify_otp(session, request.phone_number, request.otp, None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    token = create_access_token({"sub": user.phone_number})
    return {"access_token": token, "token_type": "bearer"}
