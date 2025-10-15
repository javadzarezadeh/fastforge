from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, func, select

from ..auth import get_current_user, role_required
from ..database import get_session
from ..models.user import Role, User, UserRoleLink

router = APIRouter(
    prefix="/users", tags=["users"], responses={404: {"description": "Not found"}}
)


class UserResponse(BaseModel):
    id: str
    phone_number: str
    email: str | None = (
        None  # Use str to accommodate both valid emails and hashed values after soft deletion
    )
    roles: list[str] = []


class UserUpdate(BaseModel):
    roles: list[str] | None = None


class AdminUserUpdate(BaseModel):
    roles: list[str] | None = None


class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int
    page: int
    size: int


@router.get("/me", response_model=UserResponse)
async def get_authenticated_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user's information.

    Args:
        current_user: The authenticated user object

    Returns:
        UserResponse: The current user's information
    """
    return UserResponse(
        id=str(current_user.id),
        phone_number=current_user.phone_number,
        email=current_user.email,  # This will be the raw value from the database, which might be hashed after soft deletion
        roles=[role.name for role in current_user.roles],
    )


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Update current user's information (non-admins can't change roles).
    Note: Phone number and email updates must be done through the dedicated endpoints in auth.py
    that include verification for security.

    Args:
        user_update: The user update data
        current_user: The authenticated user object
        session: Database session dependency

    Returns:
        UserResponse: The updated user's information

    Raises:
        HTTPException: If non-admin tries to update roles
    """

    # Role updates (admin only)
    if user_update.roles and "admin" not in [role.name for role in current_user.roles]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update roles"
        )
    if user_update.roles:
        # Clear existing roles
        user_roles = session.exec(
            select(UserRoleLink).where(UserRoleLink.user_id == current_user.id)
        ).all()
        for user_role in user_roles:
            session.delete(user_role)
        # Add new roles
        for role_name in user_update.roles:
            role = session.exec(select(Role).where(Role.name == role_name)).first()
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role '{role_name}' does not exist",
                )
            user_role = UserRoleLink(user_id=current_user.id, role_id=role.id)
            session.add(user_role)

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return UserResponse(
        id=str(current_user.id),
        phone_number=current_user.phone_number,
        email=current_user.email,
        roles=[role.name for role in current_user.roles],
    )


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Soft delete current user by hashing identifying information.

    Args:
        current_user: The authenticated user object
        session: Database session dependency

    Returns:
        None: Indicates successful deletion
    """
    # Use the soft delete method with identifier hashing
    current_user.soft_delete_with_hashed_identifiers()

    # Update the user in the database
    session.add(current_user)
    session.commit()
    return None


@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(
    user_id: str,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Get user by ID (admin only).

    Args:
        user_id: The ID of the user to retrieve
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserResponse: The requested user's information

    Raises:
        HTTPException: If user ID is invalid or user not found
    """
    try:
        user = session.exec(
            select(User).where((User.id == UUID(user_id)) & (User.deleted_at.is_(None)))
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return UserResponse(
        id=str(user.id),
        phone_number=user.phone_number,
        email=user.email,
        roles=[role.name for role in user.roles],
    )


@router.get("/", response_model=UserListResponse)
async def get_all_users(
    page: int = 0,
    size: int = 20,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Get all users with pagination (admin only).

    Args:
        page: Page number (0-indexed)
        size: Number of users per page
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserListResponse: List of users with pagination info
    """
    offset = page * size

    # Count total users efficiently with COUNT query
    total = session.exec(
        select(func.count(User.id)).where(User.deleted_at.is_(None))
    ).one()

    # Get paginated users
    users = session.exec(
        select(User).where(User.deleted_at.is_(None)).offset(offset).limit(size)
    ).all()

    user_responses = []
    for user in users:
        user_responses.append(
            UserResponse(
                id=str(user.id),
                phone_number=user.phone_number,
                email=user.email,
                roles=[role.name for role in user.roles],
            )
        )

    return UserListResponse(users=user_responses, total=total, page=page, size=size)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user_by_id(
    user_id: str,
    user_update: AdminUserUpdate,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Update user by ID (admin only).

    Args:
        user_id: The ID of the user to update
        user_update: The user update data
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserResponse: The updated user's information

    Raises:
        HTTPException: If user ID is invalid or user not found
    """
    try:
        user = session.exec(
            select(User).where((User.id == UUID(user_id)) & (User.deleted_at.is_(None)))
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Update roles if provided
    if user_update.roles is not None:
        # Clear existing roles
        user_roles = session.exec(
            select(UserRoleLink).where(UserRoleLink.user_id == user.id)
        ).all()
        for user_role in user_roles:
            session.delete(user_role)
        # Add new roles
        for role_name in user_update.roles:
            role = session.exec(select(Role).where(Role.name == role_name)).first()
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role '{role_name}' does not exist",
                )
            user_role = UserRoleLink(user_id=user.id, role_id=role.id)
            session.add(user_role)

    session.add(user)
    session.commit()
    session.refresh(user)

    return UserResponse(
        id=str(user.id),
        phone_number=user.phone_number,
        email=user.email,
        roles=[role.name for role in user.roles],
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_by_id(
    user_id: str,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Soft delete user by ID (admin only).

    Args:
        user_id: The ID of the user to delete
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        None: Indicates successful deletion
    """
    try:
        user = session.exec(
            select(User).where((User.id == UUID(user_id)) & (User.deleted_at.is_(None)))
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Use the soft delete method with identifier hashing
    user.soft_delete_with_hashed_identifiers()

    # Update the user in the database
    session.add(user)
    session.commit()
    return None


@router.post("/{user_id}/roles/{role_name}", response_model=UserResponse)
async def assign_role_to_user(
    user_id: str,
    role_name: str,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Assign a role to a user (admin only).

    Args:
        user_id: The ID of the user to assign the role to
        role_name: The name of the role to assign
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserResponse: The updated user's information

    Raises:
        HTTPException: If user ID is invalid, user not found, or role doesn't exist
    """
    try:
        user = session.exec(
            select(User).where((User.id == UUID(user_id)) & (User.deleted_at.is_(None)))
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Check if role exists
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Check if user already has this role
    existing_user_role = session.exec(
        select(UserRoleLink).where(
            (UserRoleLink.user_id == user.id) & (UserRoleLink.role_id == role.id)
        )
    ).first()
    if existing_user_role:
        # User already has this role, return current info
        return UserResponse(
            id=str(user.id),
            phone_number=user.phone_number,
            email=user.email,
            roles=[role.name for role in user.roles],
        )

    # Assign the role to the user
    user_role = UserRoleLink(user_id=user.id, role_id=role.id)
    session.add(user_role)
    session.commit()
    session.refresh(user)

    return UserResponse(
        id=str(user.id),
        phone_number=user.phone_number,
        email=user.email,
        roles=[role.name for role in user.roles],
    )


@router.delete("/{user_id}/roles/{role_name}", response_model=UserResponse)
async def remove_role_from_user(
    user_id: str,
    role_name: str,
    current_user: User = Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Remove a role from a user (admin only).

    Args:
        user_id: The ID of the user to remove the role from
        role_name: The name of the role to remove
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserResponse: The updated user's information

    Raises:
        HTTPException: If user ID is invalid, user not found, or role doesn't exist
    """
    try:
        user = session.exec(
            select(User).where((User.id == UUID(user_id)) & (User.deleted_at.is_(None)))
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID"
        )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Check if role exists
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Remove the role from the user
    user_role = session.exec(
        select(UserRoleLink).where(
            (UserRoleLink.user_id == user.id) & (UserRoleLink.role_id == role.id)
        )
    ).first()
    if not user_role:
        # User doesn't have this role, return current info
        return UserResponse(
            id=str(user.id),
            phone_number=user.phone_number,
            email=user.email,
            roles=[role.name for role in user.roles],
        )

    session.delete(user_role)
    session.commit()
    session.refresh(user)

    return UserResponse(
        id=str(user.id),
        phone_number=user.phone_number,
        email=user.email,
        roles=[role.name for role in user.roles],
    )
