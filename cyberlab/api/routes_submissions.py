"""Flag submission and grading endpoints."""
from pydantic import BaseModel
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from cyberlab.db.database import get_db
from cyberlab.db.models import User, Challenge, Submission, AuditLog
from cyberlab.api.deps import get_current_user
from cyberlab.services.ctfd_client import ctfd_client
from cyberlab.services.lms_service import lms_service

router = APIRouter(prefix="/api/challenges", tags=["submissions"])


class SubmissionRequest(BaseModel):
    flag: str


@router.post("/{challenge_id}/submit")
async def submit_challenge_flag(
    challenge_id: str,
    req: SubmissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Validate flag submission against CTFd backend and update student competencies.
    """
    chal = db.query(Challenge).filter(Challenge.id == challenge_id, Challenge.enabled == True).first()
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found.")

    # Check if user already solved it
    existing_solve = db.query(Submission).filter(
        Submission.user_id == current_user.id,
        Submission.challenge_id == challenge_id,
        Submission.is_correct == True,
    ).first()

    if existing_solve:
        return {
            "is_correct": True,
            "points_awarded": 0,
            "message": "Challenge already solved! You have previously completed this investigation.",
            "already_solved": True,
        }

    # Validate flag with CTFd engine
    is_correct, points_awarded, msg = await ctfd_client.submit_flag(
        challenge_id=challenge_id,
        submitted_flag=req.flag,
        user_id=current_user.id,
        expected_flag=chal.flag,
        points=chal.points,
    )

    sub = Submission(
        user_id=current_user.id,
        challenge_id=challenge_id,
        submitted_flag=req.flag,
        is_correct=is_correct,
        points_awarded=points_awarded,
        created_at=datetime.utcnow(),
    )
    db.add(sub)

    # Log audit event
    db.add(AuditLog(
        timestamp=datetime.utcnow(),
        user_id=current_user.id,
        event_type="SUBMISSION_SUCCESS" if is_correct else "SUBMISSION_FAILED",
        severity="INFO" if is_correct else "WARN",
        details_json={
            "challenge_id": challenge_id,
            "is_correct": is_correct,
            "points": points_awarded,
        },
    ))
    db.commit()

    if is_correct:
        # Update student's competency matrix in LMS service
        lms_service.update_student_competency(db, current_user.id, challenge_id)

    return {
        "is_correct": is_correct,
        "points_awarded": points_awarded,
        "message": msg,
        "already_solved": False,
    }

