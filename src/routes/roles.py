from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..auth import role_required
from ..database import get_session
from ..models.user import Role, User, UserRoleLink
from ..routes.users import UserListResponse, UserResponse


# Response models using proper Pydantic schemas
class RoleResponse(BaseModel):
    name: str
    description: str | None = None


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)


class RoleUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=255)


router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("/", response_model=list[str])
async def get_all_roles(
    session: Session = Depends(get_session),
    current_user=Depends(role_required(["admin"])),
):
    """
    Get all roles (admin only).

    Args:
        session: Database session dependency
        current_user: The authenticated admin user object

    Returns:
        list[str]: A list of all role names
    """
    roles = session.exec(select(Role)).all()
    return [role.name for role in roles]


@router.get("/{role_name}", response_model=RoleResponse)
async def get_role_by_name(
    role_name: str,
    current_user=Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Get role by name (admin only).

    Args:
        role_name: The name of the role to retrieve
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        RoleResponse: The requested role's information

    Raises:
        HTTPException: If role not found
    """
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    return RoleResponse(name=role.name, description=role.description)


@router.post("/", response_model=str)
async def create_new_role(
    role_create: RoleCreate,
    session: Session = Depends(get_session),
    current_user=Depends(role_required(["admin"])),
):
    """
    Create a new role (admin only).

    Args:
        role_create: The role creation data
        session: Database session dependency
        current_user: The authenticated admin user object

    Returns:
        str: The name of the created role

    Raises:
        HTTPException: If role already exists
    """
    if session.exec(select(Role).where(Role.name == role_create.name)).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists"
        )
    role = Role(name=role_create.name, description=role_create.description)
    session.add(role)
    session.commit()
    return role.name


@router.put("/{role_name}", response_model=RoleResponse)
async def update_role_by_name(
    role_name: str,
    role_update: RoleUpdate,
    current_user=Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Update role by name (admin only).

    Args:
        role_name: The name of the role to update
        role_update: The role update data
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        RoleResponse: The updated role's information

    Raises:
        HTTPException: If role not found
    """
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Update the role with provided data
    if role_update.description is not None:
        role.description = role_update.description

    session.add(role)
    session.commit()
    session.refresh(role)

    return RoleResponse(name=role.name, description=role.description)


@router.delete("/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_by_name(
    role_name: str,
    current_user=Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Delete role by name (soft delete by marking as inactive) (admin only).

    Args:
        role_name: The name of the role to delete
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        None: Indicates successful deletion

    Raises:
        HTTPException: If role not found or if trying to delete a role that's assigned to users
    """
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Check if role is assigned to any users
    user_role = session.exec(
        select(UserRoleLink).where(UserRoleLink.role_id == role.id)
    ).first()
    if user_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete role that is assigned to users",
        )

    session.delete(role)
    session.commit()
    return None


@router.get("/{role_name}/users", response_model=UserListResponse)
async def get_users_by_role(
    role_name: str,
    page: int = 0,
    size: int = 20,
    current_user=Depends(role_required(["admin"])),
    session: Session = Depends(get_session),
):
    """
    Get all users with a specific role (admin only).

    Args:
        role_name: The name of the role to filter users by
        page: Page number (0-indexed)
        size: Number of users per page
        current_user: The authenticated admin user object
        session: Database session dependency

    Returns:
        UserListResponse: List of users with the specified role with pagination info
    """
    offset = page * size

    # Get the role
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )

    # Count total users with this role
    stmt = (
        select(User)
        .join(UserRoleLink)
        .where((UserRoleLink.role_id == role.id) & (User.deleted_at.is_(None)))
    )
    total = session.exec(stmt).all()
    total_count = len(total)

    # Get paginated users with this role
    stmt_paginated = (
        select(User)
        .join(UserRoleLink)
        .where((UserRoleLink.role_id == role.id) & (User.deleted_at.is_(None)))
        .offset(offset)
        .limit(size)
    )
    users = session.exec(stmt_paginated).all()

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

    return UserListResponse(
        users=user_responses, total=total_count, page=page, size=size
    )
