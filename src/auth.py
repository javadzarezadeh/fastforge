import os
import random
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, status
from jose import jwt
from sqlmodel import Session, select

from .models.user import User
from .sms_service import MockSMSService

SECRET_KEY = os.getenv("SECRET_KEY", "your-secure-random-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_EXPIRE_MINUTES = 5

ph = PasswordHasher()

redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True
)


def generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))


def store_otp(phone_number: str, otp: str) -> None:
    redis_client.setex(
        f"otp:{phone_number}", timedelta(minutes=OTP_EXPIRE_MINUTES), otp
    )


def verify_otp_stored(phone_number: str, otp: str) -> bool:
    stored_otp = redis_client.get(f"otp:{phone_number}")
    if stored_otp and stored_otp == otp:
        redis_client.delete(f"otp:{phone_number}")
        return True
    return False


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_user(
    session: Session, phone_number: str, password: Optional[str] = None
) -> User:
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered",
        )
    user = User(
        phone_number=phone_number,
        hashed_password=hash_password(password) if password else None,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def register_user(
    session: Session,
    phone_number: str,
    password: Optional[str],
    sms_service: MockSMSService,
) -> dict:
    otp = generate_otp()
    store_otp(phone_number, otp)
    if not sms_service.send_otp(phone_number, otp):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP",
        )
    return {"message": "OTP sent for phone verification"}


def verify_otp(
    session: Session, phone_number: str, otp: str, password: Optional[str]
) -> Optional[User]:
    if not verify_otp_stored(phone_number, otp):
        return None
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if not user:
        user = create_user(session, phone_number, password)
    return user


def send_login_otp(
    session: Session, phone_number: str, sms_service: MockSMSService
) -> dict:
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    otp = generate_otp()
    store_otp(phone_number, otp)
    if not sms_service.send_otp(phone_number, otp):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP",
        )
    return {"message": "OTP sent for login"}


def verify_password_login(
    session: Session, phone_number: str, password: str
) -> Optional[User]:
    user = session.exec(select(User).where(User.phone_number == phone_number)).first()
    if not user or not user.hashed_password:
        return None
    if verify_password(user.hashed_password, password):
        return user
    return None
