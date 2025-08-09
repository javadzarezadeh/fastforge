from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, List, Optional

from pydantic import StringConstraints
from sqlmodel import Field, Relationship, SQLModel

from .role import UserRole

if TYPE_CHECKING:
    from .role import Role


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    phone_number: Annotated[str, StringConstraints(pattern=r"^\+?[1-9]\d{1,14}$")] = (
        Field(unique=True, index=True)
    )
    hashed_password: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: Optional[datetime] = None
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRole)
