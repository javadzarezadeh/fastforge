from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..auth import role_required
from ..database import get_session
from ..models.user import Role

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("/", response_model=list[str])
async def list_roles(
    session: Session = Depends(get_session),
    current_user=Depends(role_required(["admin"])),
):
    roles = session.exec(select(Role)).all()
    return [role.name for role in roles]


@router.post("/", response_model=str)
async def create_role(
    name: str,
    session: Session = Depends(get_session),
    current_user=Depends(role_required(["admin"])),
):
    if session.exec(select(Role).where(Role.name == name)).first():
        raise HTTPException(status_code=400, detail="Role already exists")
    role = Role(name=name)
    session.add(role)
    session.commit()
    return role.name
