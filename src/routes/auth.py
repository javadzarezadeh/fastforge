"""
Authentication API routes and endpoints.

This module contains all authentication-related API endpoints such as
OTP requests, user login, and token verification.
"""

from datetime import datetime, timedelta, timezone

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlmodel import Session, select

from ..auth import (
    create_access_token,
    create_refresh_token,
    delete_phone_change_request,
    generate_otp,
    get_current_user,
    get_phone_change_request,
    send_login_otp,
    store_otp,
    store_phone_change_request,
    store_refresh_token,
    validate_phone_number,
    verify_otp_and_create_user,
    verify_otp_stored,
)
from ..config import Config
from ..database import get_session
from ..email_service import EmailService, get_email_service
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
    refresh_token: str
    token_type: str = "bearer"


@router.post("/request-otp", tags=["auth"])
@limiter.limit("3/minute")
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


@router.post("/login", response_model=TokenResponse, tags=["auth"])
@limiter.limit("3/minute")
async def authenticate_user_with_otp(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    Authenticate user with OTP and return JWT token.
    Supports both phone number and email login if user has added an email.

    Args:
        request: The incoming HTTP request
        form_data: OAuth2 password form data (phone/email as username, OTP as password)
        session: Database session dependency

    Returns:
        A dictionary with access token, refresh token and token type

    Raises:
        HTTPException: If OTP is invalid or phone number format is invalid
    """
    identifier = form_data.username
    otp_code = form_data.password
    # No password/OTP: send OTP
    if not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP required; use POST /auth/request-otp first",
        )

    # Check if identifier is a phone number or email
    if validate_phone_number(identifier):
        # Login with phone number
        user = verify_otp_and_create_user(session, identifier, otp_code)
    elif "@" in identifier and "." in identifier:
        # Login with email - find user by email and verify OTP
        user = session.exec(
            select(User).where((User.email == identifier) & (User.deleted_at.is_(None)))
        ).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )

        # Verify OTP for the user's phone number (the primary identifier)
        if not verify_otp_stored(user.phone_number, otp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number or email format",
        )

    # Generate tokens
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token()

    # Store the refresh token in the user record
    store_refresh_token(user, refresh_token, session)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/verify-login-otp", response_model=TokenResponse, tags=["auth"])
@limiter.limit("3/minute")
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
        A dictionary with access token, refresh token and token type

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

    # Generate tokens
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token()

    # Store the refresh token in the user record
    store_refresh_token(user, refresh_token, session)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


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
        HTTPException: If secret key is invalid, user already exists,
                       or an admin user already exists
    """
    if secret_key != Config.ADMIN_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid secret key"
        )

    # Check if any admin user already exists
    existing_admin = session.exec(
        select(User).join(UserRole).join(Role).where(Role.name == "admin")
    ).first()

    if existing_admin:
        raise HTTPException(
            status_code=400,
            detail="An admin user already exists. This endpoint is disabled.",
        )

    # Check if there's an active user with this phone number
    active_user = session.exec(
        select(User).where(
            (User.phone_number == phone_number) & (User.deleted_at.is_(None))
        )
    ).first()
    if active_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists"
        )
    user = User(
        phone_number=phone_number, email=None, created_at=datetime.now(tz=timezone.utc)
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    admin_role = session.exec(select(Role).where(Role.name == "admin")).first()
    if not admin_role:
        admin_role = Role(name="admin", description="Administrator with full access")
        session.add(admin_role)
        session.commit()
        session.refresh(admin_role)
    user_role = UserRole(user_id=user.id, role_id=admin_role.id)
    session.add(user_role)
    session.commit()
    return {"message": "Admin created"}


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenResponse, tags=["auth"])
@limiter.limit("10/minute")
async def refresh_access_token(
    request: Request,
    data: RefreshTokenRequest,
    session: Session = Depends(get_session),
):
    """
    Refresh access token using a valid refresh token.

    Args:
        request: The incoming HTTP request
        data: The refresh token request data containing the refresh token
        session: Database session dependency

    Returns:
        A dictionary with new access token, new refresh token and token type

    Raises:
        HTTPException: If refresh token is invalid or user not found
    """
    # Find user by refresh token
    user = session.exec(
        select(User).where(
            (User.refresh_token == data.refresh_token) & (User.deleted_at.is_(None))
        )
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Generate new tokens using user UUID as the subject
    access_token = create_access_token(data={"sub": str(user.id)})
    new_refresh_token = create_refresh_token()

    # Update the refresh token in the user record
    store_refresh_token(user, new_refresh_token, session)

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


class UpdateEmailRequest(BaseModel):
    email: EmailStr


class VerifyEmailRequest(BaseModel):
    verification_code: str


@router.post("/update-email", tags=["auth"])
@limiter.limit("3/minute")
async def update_user_email(
    request: Request,
    update_email_request: UpdateEmailRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    email_service: EmailService = Depends(get_email_service),
):
    """
    Update the user's email address.

    Args:
        request: The incoming HTTP request
        update_email_request: The request containing the new email address
        current_user: The currently authenticated user
        session: Database session dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If email is already registered to another user
    """
    # Check if email is already registered to another active user
    existing_user = session.exec(
        select(User).where(
            (User.email == update_email_request.email)
            & (User.deleted_at.is_(None))
            & (User.id != current_user.id)
        )
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered to another user",
        )

    # Update the user's email
    current_user.email = update_email_request.email
    current_user.is_email_verified = False  # Email needs to be verified
    current_user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
    session.add(current_user)
    session.commit()

    # Generate verification code and store it in Redis
    verification_code = (
        generate_otp()
    )  # Reusing the OTP function for email verification
    redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)
    redis_client.setex(
        f"email_verification:{update_email_request.email}",
        timedelta(minutes=Config.OTP_EXPIRE_MINUTES),
        verification_code,
    )

    # Use the email service to "send" the verification email
    await email_service.send_email(
        to_emails=[update_email_request.email],
        subject="Email Verification Code",
        body=f"Your verification code is: {verification_code}",
    )

    return {"message": "Email updated. Verification code sent to email."}


@router.post("/verify-email", tags=["auth"])
@limiter.limit("3/minute")
async def verify_user_email(
    request: Request,
    verify_email_request: VerifyEmailRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Verify the user's email address with the provided code.

    Args:
        request: The incoming HTTP request
        verify_email_request: The request containing the verification code
        current_user: The currently authenticated user
        session: Database session dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If verification code is invalid
    """
    if not current_user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email address to verify",
        )

    # Check the verification code in Redis
    redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)
    stored_code = redis_client.get(f"email_verification:{current_user.email}")

    if not stored_code or stored_code != verify_email_request.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Verification successful, update user status and remove the code from Redis
    current_user.is_email_verified = True
    current_user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
    session.add(current_user)
    session.commit()
    redis_client.delete(f"email_verification:{current_user.email}")

    return {"message": "Email verified successfully"}


class UpdatePhoneNumberRequest(BaseModel):
    phone_number: str


class VerifyPhoneNumberRequest(BaseModel):
    verification_code: str


@router.post("/update-phone-number", tags=["auth"])
@limiter.limit("3/minute")
async def request_phone_number_change(
    request: Request,
    update_phone_request: UpdatePhoneNumberRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
    sms_service: SMSService = Depends(get_sms_service),
):
    """
    Request to update the user's phone number.

    Args:
        request: The incoming HTTP request
        update_phone_request: The request containing the new phone number
        current_user: The currently authenticated user
        session: Database session dependency
        sms_service: SMS service dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If phone number is already registered to another user
    """
    # Validate phone number format using the centralized validation function
    if not validate_phone_number(update_phone_request.phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid phone number format",
        )

    # Check if phone number is already registered to another active user
    existing_user = session.exec(
        select(User).where(
            (User.phone_number == update_phone_request.phone_number)
            & (User.deleted_at.is_(None))
            & (User.id != current_user.id)
        )
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered to another user",
        )

    # Store the phone number change request in Redis
    store_phone_change_request(str(current_user.id), update_phone_request.phone_number)

    # Generate OTP and send it to the new phone number
    otp = generate_otp()
    store_otp(update_phone_request.phone_number, otp)
    sms_service.send_otp(update_phone_request.phone_number, otp)

    return {"message": "Verification code sent to new phone number"}


@router.post("/verify-phone-number", tags=["auth"])
@limiter.limit("3/minute")
async def verify_phone_number_change(
    request: Request,
    verify_phone_request: VerifyPhoneNumberRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Verify the new phone number with the provided code and update it.

    Args:
        request: The incoming HTTP request
        verify_phone_request: The request containing the verification code
        current_user: The currently authenticated user
        session: Database session dependency

    Returns:
        A dictionary with a success message

    Raises:
        HTTPException: If verification code is invalid or no phone number change request exists
    """
    # Get the requested phone number change
    new_phone_number = get_phone_change_request(str(current_user.id))

    if not new_phone_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No phone number change request found. Please request a change first.",
        )

    # Verify the OTP for the new phone number
    if not verify_otp_stored(new_phone_number, verify_phone_request.verification_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Verification successful, update user's phone number
    current_user.phone_number = new_phone_number
    current_user.is_phone_verified = True  # New phone number is now verified
    current_user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
    session.add(current_user)
    session.commit()

    # Delete the phone number change request
    delete_phone_change_request(str(current_user.id))

    # Revoke all refresh tokens to force re-authentication
    current_user.refresh_token = None
    session.add(current_user)
    session.commit()

    return {"message": "Phone number updated and verified successfully"}
