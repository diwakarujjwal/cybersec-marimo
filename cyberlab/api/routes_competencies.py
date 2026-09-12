"""Competency metrics and curriculum navigation routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from cyberlab.db.database import get_db
from cyberlab.db.models import User
from cyberlab.api.deps import get_current_user
from cyberlab.services.lms_service import lms_service
from cyberlab.services.ctfd_client import ctfd_client

router = APIRouter(tags=["competencies"])


@router.get("/api/competencies/my")
def get_my_competencies(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve personalized competency matrix and skill proficiency percentages."""
    return lms_service.get_student_competency_matrix(db, current_user.id)


@router.get("/api/curriculum")
def get_curriculum(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve course modules, lessons, and personalized completion statuses."""
    return lms_service.get_curriculum(db, current_user.id)


@router.get("/api/scoreboard")
async def get_scoreboard():
    """Retrieve CTFd scoreboard ranks and points."""
    return await ctfd_client.get_scoreboard()

