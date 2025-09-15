from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select

from ..auth import get_current_user, hash_password
from ..database import get_session
from ..models.user import User

router = APIRouter(
    prefix="/users", tags=["users"], responses={404: {"description": "Not found"}}
)


class UserResponse(BaseModel):
    id: str
    phone_number: str
    email: Optional[EmailStr] = None


class UserUpdate(BaseModel):
    phone_number: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user's information"""
    return UserResponse(
        id=str(current_user.id),
        phone_number=current_user.phone_number,
        email=current_user.email,
    )


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Update current user's information"""
    if (
        user_update.phone_number
        and user_update.phone_number != current_user.phone_number
    ):
        existing_user = session.exec(
            select(User).where(User.phone_number == user_update.phone_number)
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered",
            )

    if user_update.email and user_update.email != current_user.email:
        existing_email = session.exec(
            select(User).where(User.email == user_update.email)
        ).first()
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

    if user_update.phone_number:
        current_user.phone_number = user_update.phone_number
    if user_update.email is not None:
        current_user.email = user_update.email
    if user_update.password:
        current_user.hashed_password = hash_password(user_update.password)

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return UserResponse(
        id=str(current_user.id),
        phone_number=current_user.phone_number,
        email=current_user.email,
    )


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Delete current user"""
    session.delete(current_user)
    session.commit()
    return None


# Optional: Admin-only endpoint (uncomment if you add is_admin to User model)
# @router.get("/{user_id}", response_model=UserResponse)
# async def get_user_by_id(
#     user_id: str,
#     current_user: User = Depends(get_current_user),
#     session: Session = Depends(get_session)
# ):
#     """Get user by ID (admin only)"""
#     if not current_user.is_admin:
#         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
#     user = session.exec(select(User).where(User.id == user_id)).first()
#     if not user:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
#     return UserResponse(
#         id=str(user.id),
#         phone_number=user.phone_number,
#         email=user.email
#     )
