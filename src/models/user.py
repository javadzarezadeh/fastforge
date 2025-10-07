import uuid
from datetime import datetime, timezone
from typing import Annotated

from pydantic import EmailStr, StringConstraints
from sqlmodel import Field, Relationship, SQLModel


class UserRole(SQLModel, table=True):
    user_id: uuid.UUID = Field(primary_key=True, foreign_key="user.id")
    role_id: uuid.UUID = Field(primary_key=True, foreign_key="role.id")


class Role(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=50)
    description: str | None = None
    users: list["User"] = Relationship(back_populates="roles", link_model=UserRole)


class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    phone_number: Annotated[str, StringConstraints(pattern=r"^\+?[1-9]\d{1,14}$")] = (
        Field(unique=True, index=True)
    )
    email: EmailStr | None = Field(default=None, unique=True, index=True)
    is_phone_verified: bool = Field(default=False)
    is_email_verified: bool = Field(default=False)
    refresh_token: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: datetime | None = Field(default=None)
    roles: list["Role"] = Relationship(back_populates="users", link_model=UserRole)
