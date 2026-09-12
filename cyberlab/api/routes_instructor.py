"""Instructor and administrative management endpoints."""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from cyberlab.db.database import get_db
from cyberlab.db.models import User, Challenge, ChallengeInstance, AuditLog, Submission
from cyberlab.api.deps import require_instructor
from cyberlab.services.lms_service import lms_service
from cyberlab.services.janitor import janitor_service
from cyberlab.services.docker_service import container_manager
from cyberlab.services.challenge_loader import challenge_loader

router = APIRouter(prefix="/api/instructor", tags=["instructor"])


class ChallengeUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    points: Optional[int] = None
    duration_minutes: Optional[int] = None


@router.get("/overview")
def get_instructor_overview(
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """Aggregate analytics: student competencies, challenge success rates, and active workloads."""
    analytics = lms_service.get_class_analytics(db)
    active_instances_count = db.query(ChallengeInstance).filter(
        ChallengeInstance.status.in_(["starting", "running"])
    ).count()

    total_submissions = db.query(Submission).count()
    correct_submissions = db.query(Submission).filter(Submission.is_correct == True).count()

    return {
        "active_instances_count": active_instances_count,
        "total_submissions": total_submissions,
        "correct_submissions": correct_submissions,
        "class_analytics": analytics,
    }


@router.get("/instances")
def list_running_instances(
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """List all active container instances with runtime stats."""
    instances = db.query(ChallengeInstance).filter(
        ChallengeInstance.status.in_(["starting", "running"])
    ).all()

    results = []
    now = datetime.utcnow()
    for inst in instances:
        uptime_seconds = int((now - inst.started_at).total_seconds()) if inst.started_at else 0
        ttl_seconds = max(0, int((inst.expires_at - now).total_seconds())) if inst.expires_at else 0
        results.append({
            "session_id": inst.id,
            "user_id": inst.user_id,
            "username": inst.user.username if inst.user else "Unknown",
            "challenge_id": inst.challenge_id,
            "status": inst.status,
            "uptime_seconds": uptime_seconds,
            "time_remaining_seconds": ttl_seconds,
            "container_id": inst.container_id[:12] if inst.container_id else None,
            "internal_port": inst.internal_port,
        })
    return results


@router.post("/instances/{session_id}/terminate")
async def terminate_student_instance(
    session_id: str,
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """Force terminate an active container instance."""
    success = await janitor_service.terminate_session(
        session_id=session_id,
        db=db,
        reason=f"INSTRUCTOR_TERMINATED_BY_{instructor.username}"
    )
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already stopped.")
    return {"message": f"Instance {session_id} successfully terminated."}


@router.patch("/challenges/{challenge_id}")
def update_challenge(
    challenge_id: str,
    req: ChallengeUpdateRequest,
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """Configure challenge settings (enabled state, points, duration)."""
    chal = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found.")

    if req.enabled is not None:
        chal.enabled = req.enabled
    if req.points is not None:
        chal.points = req.points
    if req.duration_minutes is not None:
        chal.duration_minutes = req.duration_minutes

    db.commit()
    return {"message": f"Challenge {chal.id} updated successfully."}


@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """Retrieve security audit logs (container events, submissions, timeouts)."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "user_id": l.user_id,
            "session_id": l.session_id,
            "event_type": l.event_type,
            "severity": l.severity,
            "details": l.details_json,
        }
        for l in logs
    ]


@router.post("/sync-challenges")
async def sync_challenges_endpoint(
    instructor: User = Depends(require_instructor),
    db: Session = Depends(get_db),
):
    """Re-scan challenges directory and sync with DB and CTFd."""
    count = await challenge_loader.sync_to_db_and_ctfd(db)
    return {"message": f"Successfully synchronized {count} challenge packages."}

