"""Team management: admins manage their organisation's users; the platform owner manages everyone's.

New users and password resets get a temporary password that is shown once to the admin, who
passes it on privately. Users change it from their account page.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Organization, User

router = APIRouter(prefix="/api")


class NewUserIn(BaseModel):
    email: str
    name: str | None = None
    role: str = "member"
    organization: str | None = None  # owner only; defaults to the admin's own organisation


class UserPatchIn(BaseModel):
    active: bool | None = None
    role: str | None = None


def _visible(admin: User, user: User) -> bool:
    return admin.role == "owner" or user.org_id == admin.org_id


def _target(session: Session, admin: User, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None or not _visible(admin, user):
        raise HTTPException(404, "user not found")
    if user.id == admin.id:
        raise HTTPException(422, "you cannot change your own account here")
    if user.role == "owner" and admin.role != "owner":
        raise HTTPException(403, "only the platform owner can change this account")
    return user


@router.get("/users")
def list_users(admin: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> list[dict]:
    query = select(User).join(Organization)
    if admin.role != "owner":
        query = query.where(User.org_id == admin.org_id)
    users = session.scalars(query.order_by(Organization.name, User.email)).all()
    return [auth.user_out(u) for u in users]


@router.get("/organizations")
def list_organizations(admin: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> list[str]:
    if admin.role != "owner":
        return [admin.org.name]
    return [o.name for o in session.scalars(select(Organization).order_by(Organization.name))]


@router.post("/users", status_code=201)
def add_user(body: NewUserIn, admin: User = Depends(auth.require_admin),
             session: Session = Depends(db.get_session)) -> dict:
    if body.role not in ("member", "admin"):
        raise HTTPException(422, "role must be member or admin")
    org_name = admin.org.name
    if body.organization and body.organization.strip() != org_name:
        if admin.role != "owner":
            raise HTTPException(403, "you can only add users to your own organisation")
        org_name = body.organization.strip()
    password = auth.temporary_password()
    try:
        user = auth.create_user(session, org_name, body.email, password, body.role, body.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**auth.user_out(user), "temporary_password": password}


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatchIn, admin: User = Depends(auth.require_admin),
                session: Session = Depends(db.get_session)) -> dict:
    user = _target(session, admin, user_id)
    if body.role is not None:
        if body.role not in ("member", "admin"):
            raise HTTPException(422, "role must be member or admin")
        user.role = body.role
    if body.active is not None:
        user.active = body.active
    session.commit()
    if body.active is False:
        auth.end_all_sessions(session, user)
    return auth.user_out(user)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, admin: User = Depends(auth.require_admin),
                   session: Session = Depends(db.get_session)) -> dict:
    user = _target(session, admin, user_id)
    password = auth.temporary_password()
    auth.set_password(session, user, password)
    auth.end_all_sessions(session, user)
    return {**auth.user_out(user), "temporary_password": password}
