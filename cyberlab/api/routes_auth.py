"""Authentication and LMS SSO routes."""
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from cyberlab.db.database import get_db
from cyberlab.db.models import User
from cyberlab.core.security import create_session_token
from cyberlab.services.lms_service import lms_service
from cyberlab.api.deps import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    role: str = "student"  # "student" or "instructor"


class LMSSSOTokenRequest(BaseModel):
    lms_user_id: str
    username: str
    email: str
    role: str = "student"
    shared_secret: str


@router.post("/login")
def login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """Convenience login for testing and browser demo sessions."""
    lms_uid = f"{req.role}-{req.username.lower()}"
    user = lms_service.get_or_create_student(
        db,
        lms_user_id=lms_uid,
        username=req.username,
        email=f"{req.username.lower()}@cyberlab.edu",
        role=req.role,
    )

    token = create_session_token(user.id, user.role)
    response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.post("/lms-sso")
def lms_sso_exchange(req: LMSSSOTokenRequest, response: Response, db: Session = Depends(get_db)):
    """LMS SSO Handshake: exchanges LMS identity token for CyberLab session."""
    user = lms_service.get_or_create_student(
        db,
        lms_user_id=req.lms_user_id,
        username=req.username,
        email=req.email,
        role=req.role,
    )

    token = create_session_token(user.id, user.role)
    response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax")

    return {
        "access_token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.get("/me")
def get_profile(current_user: User = Depends(get_current_user)):
    """Get profile of current authenticated student or instructor."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }

