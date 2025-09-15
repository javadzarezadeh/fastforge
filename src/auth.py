import os
import random
import string
from datetime import datetime, timedelta, timezone

import redis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session, select

from .database import get_session
from .models.user import User
from .sms_service import MockSMSService

SECRET_KEY = os.getenv("SECRET_KEY", "your-secure-random-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_EXPIRE_MINUTES = 5

ph = PasswordHasher()

# Use OAuth2PasswordBearer for simple username/password input in Swagger UI
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    description="Enter phone number as username and OTP (from POST /auth/request-otp logs) as password. New users are created automatically.",
)

redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True
)


def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return "".join(random.choices(string.digits, k=6))


def store_otp(phone_number: str, otp: str) -> None:
    """Store OTP in Redis with expiration"""
    redis_client.setex(
        f"otp:{phone_number}", timedelta(minutes=OTP_EXPIRE_MINUTES), otp
    )


def verify_otp_stored(phone_number: str, otp: str) -> bool:
    """Verify OTP from Redis"""
    stored_otp = redis_client.get(f"otp:{phone_number}")
    if stored_otp and stored_otp == otp:
        redis_client.delete(f"otp:{phone_number}")
        return True
    return False


def hash_password(password: str) -> str:
    """Hash a password using Argon2"""
    return ph.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    """Verify a password against its Argon2 hash"""
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False


def create_access_token(data: dict) -> str:
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)
) -> User:
    """Get current user from JWT token"""
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


def verify_otp(
    session: Session, phone_number: str, otp: str, email: str | None = None
) -> User:
    """Verify OTP and create user if valid"""
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
    return user


def send_login_otp(
    session: Session, phone_number: str, sms_service: MockSMSService
) -> dict:
    """Send OTP for login or registration"""
    otp = generate_otp()
    store_otp(phone_number, otp)
    sms_service.send_otp(phone_number, otp)
    return {"message": "OTP sent for login or registration"}
