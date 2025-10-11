"""Authentication utilities and helper functions."""

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

import redis
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session, select

from .config import Config
from .database import get_session
from .models.user import Role, User, UserRole
from .sms_service import MockSMSService

ALGORITHM = "HS256"
SECRET_KEY = Config.SECRET_KEY

# Use OAuth2PasswordBearer for simple username/password input in Swagger UI
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    description="Enter phone number or email as username and OTP (from POST /auth/request-otp logs) as password. New users are created automatically, with 'user' role.",
)

redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)

# OTP attempt limiting constants
MAX_OTP_ATTEMPTS = 3
OTP_ATTEMPT_WINDOW = 15  # minutes


def increment_otp_attempts(phone_number: str) -> int:
    """
    Increment the OTP attempt counter for a phone number.

    Args:
        phone_number: The phone number to track attempts for

    Returns:
        The current attempt count
    """
    key = f"otp_attempts:{phone_number}"
    current_count = redis_client.get(key)

    if current_count is None:
        # First attempt, set counter with expiration
        redis_client.setex(key, timedelta(minutes=OTP_ATTEMPT_WINDOW), "1")
        return 1
    else:
        count = int(current_count) + 1
        # Update the counter but keep the same expiration window
        redis_client.setex(key, timedelta(minutes=OTP_ATTEMPT_WINDOW), str(count))
        return count


def get_otp_attempts_remaining(phone_number: str) -> int:
    """
    Get the number of remaining OTP attempts for a phone number.

    Args:
        phone_number: The phone number to check

    Returns:
        The number of attempts remaining
    """
    key = f"otp_attempts:{phone_number}"
    current_count = redis_client.get(key)

    if current_count is None:
        return MAX_OTP_ATTEMPTS
    else:
        return max(0, MAX_OTP_ATTEMPTS - int(current_count))


def is_otp_attempt_limited(phone_number: str) -> bool:
    """
    Check if a phone number has exceeded the maximum OTP attempts.

    Args:
        phone_number: The phone number to check

    Returns:
        True if the phone number is currently limited, False otherwise
    """
    key = f"otp_attempts:{phone_number}"
    current_count = redis_client.get(key)

    if current_count is None:
        return False
    else:
        return int(current_count) > MAX_OTP_ATTEMPTS


def reset_otp_attempts(phone_number: str) -> None:
    """
    Reset the OTP attempt counter for a phone number (e.g., after successful verification).

    Args:
        phone_number: The phone number to reset attempts for
    """
    key = f"otp_attempts:{phone_number}"
    redis_client.delete(key)


def generate_otp() -> str:
    """
    Generate a 6-digit OTP (One-Time Password) for authentication.

    Returns:
        A 6-character string containing random digits
    """
    return "".join(secrets.choice("0123456789") for _ in range(6))


def store_otp(phone_number: str, otp: str) -> None:
    """
    Store OTP in Redis with expiration.

    Args:
        phone_number: The phone number associated with the OTP
        otp: The OTP code to store
    """
    redis_client.setex(
        f"otp:{phone_number}", timedelta(minutes=Config.OTP_EXPIRE_MINUTES), otp
    )


def verify_otp_stored(phone_number: str, otp: str) -> bool:
    """
    Verify OTP from Redis with attempt limiting.

    Args:
        phone_number: The phone number associated with the OTP
        otp: The OTP code to verify

    Returns:
        True if OTP is valid and exists, False otherwise
    """
    # Check if the phone number has exceeded the maximum attempts
    if is_otp_attempt_limited(phone_number):
        return False

    # Increment the attempt counter
    increment_otp_attempts(phone_number)

    stored_otp = redis_client.get(f"otp:{phone_number}")
    if stored_otp and stored_otp == otp:
        # OTP is correct, delete both the OTP and reset attempts
        redis_client.delete(f"otp:{phone_number}")
        reset_otp_attempts(phone_number)  # Reset attempt counter on success
        return True
    return False


def create_access_token(data: dict) -> str:
    """
    Create JWT token with expiration.

    Args:
        data: The data to encode in the token (typically user information)

    Returns:
        The encoded JWT token string
    """
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + timedelta(
        minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)
) -> User:
    """
    Get current user from JWT token.

    Args:
        token: The JWT token from the Authorization header
        session: Database session dependency

    Returns:
        The authenticated user object

    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        user = session.exec(select(User).where(User.id == user_id)).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def get_current_user_with_roles(
    required_roles: list[str] = None,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """
    Get current user with role check.

    Args:
        required_roles: List of roles that are allowed access
        token: The JWT token from the Authorization header
        session: Database session dependency

    Returns:
        The authenticated user object if they have required role(s)

    Raises:
        HTTPException: If user doesn't have required role(s)
    """
    user = await get_current_user(token, session)
    if required_roles:
        user_roles = [role.name for role in user.roles]
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: This action requires one of the following roles: {', '.join(required_roles)}",
            )
    return user


def role_required(required_roles: list[str]) -> Callable:
    """
    Factory function to create role-specific dependencies.

    Args:
        required_roles: List of roles that are allowed access to the endpoint

    Returns:
        A dependency function that checks user roles
    """

    async def dependency(
        token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)
    ) -> User:
        return await get_current_user_with_roles(
            required_roles=required_roles, token=token, session=session
        )

    return dependency


def verify_otp_and_create_user(
    session: Session, phone_number: str, otp: str, email: str | None = None
) -> User:
    """
    Verify OTP and create user with default 'user' role if not exists.

    Args:
        session: Database session dependency
        phone_number: The phone number to verify
        otp: The OTP code to verify
        email: Optional email address for the user

    Returns:
        The verified user object

    Raises:
        HTTPException: If OTP is invalid or email is already registered
    """
    if not verify_otp_stored(phone_number, otp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if not user:
        if email and session.exec(select(User).where(User.email == email)).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        user = User(
            phone_number=phone_number,
            is_phone_verified=True,  # Phone number is verified via OTP
            email=email,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        # Assign default 'user' role
        user_role = session.exec(select(Role).where(Role.name == "user")).first()
        if not user_role:
            user_role = Role(name="user", description="Standard user with basic access")
            session.add(user_role)
            session.commit()
            session.refresh(user_role)
        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)
        session.add(user_role_link)
        session.commit()
    else:
        # If user exists but phone isn't verified, mark it as verified
        if not user.is_phone_verified:
            user.is_phone_verified = True
            user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
            session.add(user)
            session.commit()
            session.refresh(user)
    return user


def send_login_otp(
    session: Session, phone_number: str, sms_service: "MockSMSService"
) -> dict:
    """
    Send OTP for login or registration.

    Args:
        session: Database session dependency
        phone_number: The phone number to send OTP to
        sms_service: SMS service dependency

    Returns:
        A dictionary with a success message
    """
    otp = generate_otp()
    store_otp(phone_number, otp)
    sms_service.send_otp(phone_number, otp)
    return {"message": "OTP sent for login or registration"}


def create_refresh_token() -> str:
    """
    Create a cryptographically secure refresh token.

    Returns:
        A secure refresh token string
    """
    return secrets.token_urlsafe(32)


def store_refresh_token(user: User, refresh_token: str, session: Session) -> None:
    """
    Store the refresh token in the user record.

    Args:
        user: The user object
        refresh_token: The refresh token to store
        session: Database session dependency
    """
    user.refresh_token = refresh_token
    user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
    session.add(user)
    session.commit()


def verify_refresh_token(user: User, refresh_token: str) -> bool:
    """
    Verify if the provided refresh token matches the stored one.

    Args:
        user: The user object
        refresh_token: The refresh token to verify

    Returns:
        True if the refresh token is valid, False otherwise
    """
    return user.refresh_token is not None and user.refresh_token == refresh_token


def revoke_refresh_token(user: User, session: Session) -> None:
    """
    Revoke the refresh token by clearing it from the user record.

    Args:
        user: The user object
        session: Database session dependency
    """
    user.refresh_token = None
    user.updated_at = datetime.now(tz=timezone.utc)  # Update timestamp
    session.add(user)
    session.commit()


def validate_phone_number(phone_number: str) -> bool:
    """
    Validate phone number format.

    Args:
        phone_number: The phone number to validate

    Returns:
        True if phone number format is valid, False otherwise
    """
    # Enhanced validation for international phone number format
    # Allows + followed by 1-15 digits, with the first digit being 1-9
    pattern = r"^\+?[1-9]\d{0,14}$"
    return bool(re.match(pattern, phone_number))


def store_phone_change_request(user_id: str, new_phone_number: str) -> None:
    """
    Store a phone number change request in Redis.

    Args:
        user_id: The ID of the user requesting the change
        new_phone_number: The new phone number to be verified
    """
    redis_client.setex(
        f"phone_change_request:{user_id}",
        timedelta(minutes=Config.OTP_EXPIRE_MINUTES),
        new_phone_number,
    )


def get_phone_change_request(user_id: str) -> str | None:
    """
    Get the phone number change request for a user from Redis.

    Args:
        user_id: The ID of the user

    Returns:
        The new phone number if exists, None otherwise
    """
    return redis_client.get(f"phone_change_request:{user_id}")


def delete_phone_change_request(user_id: str) -> None:
    """
    Delete the phone number change request for a user from Redis.

    Args:
        user_id: The ID of the user
    """
    redis_client.delete(f"phone_change_request:{user_id}")
