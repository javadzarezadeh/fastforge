import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import EmailStr, field_validator
from sqlmodel import Field, Relationship, SQLModel

if TYPE_CHECKING:
    from .user import User  # Forward reference for type checking


class UserRoleLink(SQLModel, table=True):
    """
    Link table for the many-to-many relationship between User and Role.
    """

    user_id: uuid.UUID = Field(default=None, foreign_key="user.id", primary_key=True)
    role_id: uuid.UUID = Field(default=None, foreign_key="role.id", primary_key=True)


class RoleBase(SQLModel):
    """
    Base class for Role model with common fields.
    """

    name: str = Field(unique=True, index=True, max_length=50)
    description: str | None = Field(default=None)


class Role(RoleBase, table=True):
    """
    Role model for user roles in the system.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    # Relationship with users through the link table
    users: list["User"] = Relationship(back_populates="roles", link_model=UserRoleLink)


class RoleRead(RoleBase):
    """
    Schema for reading Role data.
    """

    id: uuid.UUID


class UserBase(SQLModel):
    """
    Base class for User model with common fields.
    """

    phone_number: str = Field(unique=True, index=True)
    email: EmailStr | None = Field(default=None, unique=True, index=True)
    is_phone_verified: bool = Field(default=False)
    is_email_verified: bool = Field(default=False)

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, v):
        """
        Validate phone number format.
        Note: This validation is bypassed for hashed values after soft deletion.
        """
        if not v:
            raise ValueError("Phone number is required")

        # Check if this is a hashed value (typical hash length) - bypass validation
        if len(v) == 64 and all(c in "0123456789abcdef" for c in v.lower()):
            return v  # Allow hashed values

        # Basic phone number validation
        import re

        pattern = r"^\+?[1-9]\d{0,14}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid phone number format")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        """
        Validate email format if provided.
        Note: This validation is bypassed for hashed values after soft deletion.
        """
        if v is None or v.strip() == "":
            return v

        # Check if this is a hashed value (typical hash length) - bypass validation
        if len(v) == 64 and all(c in "0123456789abcdef" for c in v.lower()):
            return v  # Allow hashed values

        # EmailStr already validates the format, so we just need to return the value
        return v


class User(UserBase, table=True):
    """
    User model for the application.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    refresh_token: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: datetime | None = Field(default=None)
    deleted_at: datetime | None = Field(default=None, index=True)

    # Relationship with roles through the link table
    roles: list["Role"] = Relationship(back_populates="users", link_model=UserRoleLink)

    def soft_delete_with_hashed_identifiers(self):
        """
        Soft delete the user account by hashing identifying information
        while preserving other data for compliance purposes.
        """
        import hashlib
        import time

        # Hash the identifiers to prevent access by new users with same identifiers
        timestamp = str(time.time())
        if self.phone_number:
            self.phone_number = hashlib.sha256(
                (self.phone_number + timestamp).encode()
            ).hexdigest()
        if self.email:
            self.email = hashlib.sha256((self.email + timestamp).encode()).hexdigest()

        # Mark as deleted
        self.deleted_at = datetime.now(tz=timezone.utc)

        # Reset verification status since identifiers are now hashed
        self.is_phone_verified = False
        self.is_email_verified = False

        # Clear refresh token for security
        self.refresh_token = None


class UserCreate(UserBase):
    """
    Schema for creating a new User.
    """

    pass
