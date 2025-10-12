import uuid
from datetime import datetime, timezone

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
    phone_number: str = Field(unique=True, index=True)
    email: str | None = Field(default=None, unique=True, index=True)
    is_phone_verified: bool = Field(default=False)
    is_email_verified: bool = Field(default=False)
    refresh_token: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: datetime | None = Field(default=None)
    deleted_at: datetime | None = Field(default=None, index=True)
    roles: list["Role"] = Relationship(back_populates="users", link_model=UserRole)

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
