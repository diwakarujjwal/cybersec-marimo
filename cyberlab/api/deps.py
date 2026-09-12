"""API dependencies and authentication resolvers."""
from typing import Optional
from fastapi import Depends, HTTPException, Header, Cookie
from sqlalchemy.orm import Session

from cyberlab.db.database import get_db
from cyberlab.db.models import User
from cyberlab.core.security import verify_session_token


async def get_current_user(
    authorization: Optional[str] = Header(None),
    session_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db),
) -> User:
    """Resolve current authenticated user from Bearer header or cookie."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    elif session_token:
        token = session_token

    if not token:
        # For development / initial access fallback to default demo student
        user = db.query(User).filter(User.lms_user_id == "demo-student-01").first()
        if user:
            return user
        raise HTTPException(status_code=401, detail="Authentication credentials required.")

    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User account not found.")

    return user


async def require_instructor(user: User = Depends(get_current_user)) -> User:
    """Enforce that the requesting user is an instructor or admin."""
    if user.role not in ["instructor", "admin"]:
        raise HTTPException(status_code=403, detail="Instructor authorization required.")
    return user

