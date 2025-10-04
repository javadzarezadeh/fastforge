"""
Authentication API routes and endpoints.

This module contains all authentication-related API endpoints such as
OTP requests, user login, and token verification.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlmodel import Session, select

from ..auth import (
    create_access_token,
    send_login_otp,
    validate_phone_number,
    verify_otp_and_create_user,
)
from ..config import Config
from ..database import get_session
from ..models.user import Role, User, UserRole
from ..sms_service import SMSService, get_sms_service

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/auth", tags=["auth"])


# Input models
class OTPRequest(BaseModel):
    phone_number: str


class VerifyOTPRequest(BaseModel):
    phone_number: str
    otp: str
    email: EmailStr | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


@router.post("/request-otp", tags=["auth"])
@limiter.limit("5/minute")
async def request_otp(
    request: Request,
    data: OTPRequest,
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(get_sms_service),
):
    """
    Request OTP for login or registration.

    Args:
        request: The incoming HTTP request
        data: The OTP request data containing phone number
        session: Database session dependency
        sms_service: SMS service dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If phone number format is invalid
    """
    # Validate phone number format
    if not validate_phone_number(data.phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number format",
        )
    return send_login_otp(session, data.phone_number, sms_service)


@router.post("/login", tags=["auth"])
@limiter.limit("5/minute")
async def authenticate_user_with_otp(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    Authenticate user with OTP and return JWT token.

    Args:
        request: The incoming HTTP request
        form_data: OAuth2 password form data (phone as username, OTP as password)
        session: Database session dependency

    Returns:
        A dictionary with access token and token type

    Raises:
        HTTPException: If OTP is invalid or phone number format is invalid
    """
    phone_number = form_data.username
    otp_code = form_data.password
    # No password/OTP: send OTP
    if not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP required; use POST /auth/request-otp first",
        )

    # Validate phone number format
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number format",
        )

    # Verify OTP and create user if needed
    user = verify_otp_and_create_user(session, phone_number, otp_code)
    access_token = create_access_token(data={"sub": user.phone_number})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/verify-login-otp", response_model=TokenResponse, tags=["auth"])
@limiter.limit("5/minute")
async def verify_login_otp(
    request: Request, data: VerifyOTPRequest, session: Session = Depends(get_session)
):
    """
    Verify login OTP and return JWT token.

    Args:
        request: The incoming HTTP request
        data: The OTP verification data containing phone number, OTP, and optional email
        session: Database session dependency

    Returns:
        A dictionary with access token and token type

    Raises:
        HTTPException: If OTP is invalid or phone number format is invalid
    """
    # Validate phone number format
    if not validate_phone_number(data.phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number format",
        )
    user = verify_otp_and_create_user(session, data.phone_number, data.otp, data.email)
    access_token = create_access_token(data={"sub": user.phone_number})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/create-admin")
async def create_admin_user(
    phone_number: str, secret_key: str, session: Session = Depends(get_session)
):
    """
    Create an admin user with the specified phone number.

    Args:
        phone_number: The phone number for the admin user
        secret_key: The secret key required to create an admin
        session: Database session dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If secret key is invalid or user already exists
    """
    if secret_key != Config.ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid secret key")
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if user:
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(
        phone_number=phone_number, email=None, created_at=datetime.now(tz=timezone.utc)
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    admin_role = session.exec(select(Role).where(Role.name == "admin")).first()
    if not admin_role:
        admin_role = Role(name="admin")
        session.add(admin_role)
        session.commit()
        session.refresh(admin_role)
    user_role = UserRole(user_id=user.id, role_id=admin_role.id)
    session.add(user_role)
    session.commit()
    return {"message": "Admin created"}
