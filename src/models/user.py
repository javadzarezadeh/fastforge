from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from pydantic import constr
from sqlmodel import Field, Relationship, SQLModel

if TYPE_CHECKING:
    from .role import Role


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    phone_number: str = Field(
        unique=True, index=True, sa_type=constr(pattern=r"^\+?[1-9]\d{1,14}$")
    )
    otp_secret: Optional[str] = Field(default=None, max_length=32)  # For TOTP
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: Optional[datetime] = None
    roles: List["Role"] = Relationship(back_populates="users", link_model="UserRole")
