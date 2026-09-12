"""Challenge catalog and hint management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from cyberlab.db.database import get_db
from cyberlab.db.models import Challenge, User, Submission
from cyberlab.api.deps import get_current_user
from cyberlab.services.ctfd_client import ctfd_client

router = APIRouter(prefix="/api/challenges", tags=["challenges"])


@router.get("")
def list_challenges(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all enabled challenges with user's solved state."""
    challenges = db.query(Challenge).filter(Challenge.enabled == True).all()
    solved = set(
        s[0]
        for s in db.query(Submission.challenge_id).filter(
            Submission.user_id == current_user.id,
            Submission.is_correct == True,
        ).all()
    )

    results = []
    for c in challenges:
        results.append({
            "id": c.id,
            "title": c.title,
            "category": c.category,
            "difficulty": c.difficulty,
            "points": c.points,
            "duration_minutes": c.duration_minutes,
            "environment_type": c.environment_type,
            "is_solved": c.id in solved,
        })
    return results


@router.get("/{challenge_id}")
def get_challenge_detail(
    challenge_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get challenge scenario briefing, objectives, and hint list."""
    chal = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found.")

    is_solved = db.query(Submission).filter(
        Submission.user_id == current_user.id,
        Submission.challenge_id == challenge_id,
        Submission.is_correct == True,
    ).first() is not None

    # Sanitize hints (hide hint content unless already unlocked)
    unlocked_ids = ctfd_client._mock_unlocked_hints.get(f"{current_user.id}:{challenge_id}", [])
    sanitized_hints = []
    for h in chal.hints or []:
        is_unlocked = h.get("id") in unlocked_ids
        sanitized_hints.append({
            "id": h.get("id"),
            "penalty": h.get("penalty", 10),
            "is_unlocked": is_unlocked,
            "content": h.get("content") if is_unlocked else "Hint locked. Click unlock to reveal.",
        })

    return {
        "id": chal.id,
        "title": chal.title,
        "category": chal.category,
        "difficulty": chal.difficulty,
        "points": chal.points,
        "duration_minutes": chal.duration_minutes,
        "scenario_md": chal.scenario_md,
        "objectives": chal.objectives_json or [],
        "environment_type": chal.environment_type,
        "is_solved": is_solved,
        "hints": sanitized_hints,
    }


@router.post("/{challenge_id}/hints/{hint_id}/unlock")
async def unlock_hint(
    challenge_id: str,
    hint_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Unlock a hint with point deduction."""
    chal = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found.")

    success, content, penalty = await ctfd_client.unlock_hint(
        challenge_id=challenge_id,
        hint_id=hint_id,
        user_id=current_user.id,
        hints_list=chal.hints,
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to unlock hint.")

    return {
        "hint_id": hint_id,
        "content": content,
        "penalty": penalty,
        "message": f"Hint unlocked. {penalty} points will be deducted from this solve.",
    }

