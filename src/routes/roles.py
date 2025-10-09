from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from ..auth import role_required
from ..database import get_session
from ..models.user import Role

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


@router.post("/", response_model=str)
async def create_new_role(
    name: str,
    description: str = None,
    session: Session = Depends(get_session),
    current_user=Depends(role_required(["admin"])),
):
    """
    Create a new role (admin only).

    Args:
        name: The name of the new role
        description: Optional description of what the role can do
        session: Database session dependency
        current_user: The authenticated admin user object

    Returns:
        str: The name of the created role

    Raises:
        HTTPException: If role already exists
    """
    if session.exec(select(Role).where(Role.name == name)).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists"
        )
    role = Role(name=name, description=description)
    session.add(role)
    session.commit()
    return role.name
