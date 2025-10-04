"""Authentication utilities and helper functions."""

from datetime import datetime, timedelta, timezone
from typing import Callable

import redis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
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

ph = PasswordHasher()

# Use OAuth2PasswordBearer for simple username/password input in Swagger UI
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    description="Enter phone number as username and OTP (from POST /auth/request-otp logs) as password. New users are created automatically, with 'user' role.",
)

redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)


def generate_otp() -> str:
    """
    Generate a 6-digit OTP (One-Time Password) for authentication.

    Returns:
        A 6-character string containing random digits
    """
    import random

    return "".join(random.choices("0123456789", k=6))


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
    Verify OTP from Redis.

    Args:
        phone_number: The phone number associated with the OTP
        otp: The OTP code to verify

    Returns:
        True if OTP is valid and exists, False otherwise
    """
    stored_otp = redis_client.get(f"otp:{phone_number}")
    if stored_otp and stored_otp == otp:
        redis_client.delete(f"otp:{phone_number}")
        return True
    return False


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.

    Args:
        password: The plain text password to hash

    Returns:
        The hashed password
    """
    return ph.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    """
    Verify a password against its Argon2 hash.

    Args:
        hashed_password: The stored hashed password
        password: The plain text password to verify

    Returns:
        True if password matches the hash, False otherwise
    """
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
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
        phone_number: str = payload.get("sub")
        if not phone_number:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        user = session.exec(
            select(User).where(User.phone_number == phone_number)
        ).first()
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
                detail=f"Requires one of: {', '.join(required_roles)}",
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
            hashed_password=None,  # Password can be set later via /users/me
            email=email,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        # Assign default 'user' role
        user_role = session.exec(select(Role).where(Role.name == "user")).first()
        if not user_role:
            user_role = Role(name="user")
            session.add(user_role)
            session.commit()
            session.refresh(user_role)
        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)
        session.add(user_role_link)
        session.commit()
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


def validate_phone_number(phone_number: str) -> bool:
    """
    Validate phone number format.

    Args:
        phone_number: The phone number to validate

    Returns:
        True if phone number format is valid, False otherwise
    """
    import re

    # Basic validation for international phone number format
    pattern = r"^\+?[1-9]\d{1,14}$"
    return bool(re.match(pattern, phone_number))
