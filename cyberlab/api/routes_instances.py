"""Container instance lifecycle management endpoints."""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pathlib import Path

from cyberlab.core.config import settings
from cyberlab.core.security import generate_secure_token, sanitize_container_view
from cyberlab.db.database import get_db
from cyberlab.db.models import User, Challenge, ChallengeInstance, AuditLog
from cyberlab.api.deps import get_current_user
from cyberlab.services.docker_service import container_manager
from cyberlab.services.janitor import janitor_service

router = APIRouter(tags=["instances"])


@router.post("/api/challenges/{challenge_id}/start")
async def start_challenge_instance(
    challenge_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Start or retrieve isolated challenge environment for the current student.
    Enforces per-student quotas and global resource limits.
    """
    chal = (
        db.query(Challenge)
        .filter(Challenge.id == challenge_id, Challenge.enabled == True)
        .first()
    )
    if not chal:
        raise HTTPException(
            status_code=404, detail="Challenge not found or currently disabled."
        )

    # 1. Check if user already has an active session for this challenge
    existing_instance = (
        db.query(ChallengeInstance)
        .filter(
            ChallengeInstance.user_id == current_user.id,
            ChallengeInstance.challenge_id == challenge_id,
            ChallengeInstance.status.in_(["starting", "running"]),
        )
        .first()
    )

    now = datetime.utcnow()
    if existing_instance:
        if existing_instance.expires_at > now:
            # Check if container process is actually alive and port is listening
            is_alive = await container_manager.is_instance_alive(
                existing_instance.container_id or "",
                existing_instance.id,
                existing_instance.internal_port,
            )
            if is_alive:
                time_remaining = int(
                    (existing_instance.expires_at - now).total_seconds()
                )
                return {
                    "id": existing_instance.id,
                    "challenge_id": chal.id,
                    "status": existing_instance.status,
                    "proxy_path": f"/session/{existing_instance.id}/?access_token={existing_instance.proxy_token}&token={existing_instance.proxy_token}",
                    "environment_type": chal.environment_type,
                    "time_remaining_seconds": time_remaining,
                    "message": "Connected to existing active session.",
                }
            else:
                # Process died (e.g. server reloaded or killed) -> clean up and launch fresh
                await janitor_service.terminate_session(
                    existing_instance.id,
                    db,
                    current_user.id,
                    "AUTO_RECOVER_DEAD_SESSION",
                )
                existing_instance = None
        else:
            # Reclaim expired instance
            await janitor_service.terminate_session(
                existing_instance.id, db, current_user.id, "AUTO_EXPIRED"
            )
            existing_instance = None

    # 2. Check per-student quota
    active_user_instances = (
        db.query(ChallengeInstance)
        .filter(
            ChallengeInstance.user_id == current_user.id,
            ChallengeInstance.status.in_(["starting", "running"]),
        )
        .all()
    )

    if len(active_user_instances) >= settings.MAX_INSTANCES_PER_STUDENT:
        # Automatically clean up oldest session to allow smooth student transition
        oldest = active_user_instances[0]
        await janitor_service.terminate_session(
            oldest.id, db, current_user.id, "QUOTA_ROTATION"
        )

    # 3. Check global resource limits
    global_active = (
        db.query(ChallengeInstance)
        .filter(ChallengeInstance.status.in_(["starting", "running"]))
        .count()
    )

    if global_active >= settings.MAX_GLOBAL_INSTANCES:
        raise HTTPException(
            status_code=503,
            detail="Platform capacity reached. Please wait for an active instance to free up.",
        )

    # 4. Resolve challenge package directory
    chal_path = settings.CHALLENGES_DIR / challenge_id
    if not chal_path.exists():
        raise HTTPException(
            status_code=500, detail="Challenge package directory missing on host."
        )

    # 5. Launch container
    proxy_token = generate_secure_token(32)
    duration_minutes = min(chal.duration_minutes, settings.MAX_INSTANCE_TTL_MINUTES)
    expires_at = now + timedelta(minutes=duration_minutes)

    instance = ChallengeInstance(
        user_id=current_user.id,
        challenge_id=chal.id,
        proxy_token=proxy_token,
        internal_port=0,
        status="starting",
        started_at=now,
        expires_at=expires_at,
        last_heartbeat_at=now,
    )
    db.add(instance)
    db.commit()
    db.refresh(instance)

    try:
        container_res = await container_manager.launch_challenge_instance(
            session_id=instance.id,
            challenge_id=chal.id,
            challenge_path=chal_path,
            environment_type=chal.environment_type,
        )

        instance.container_id = container_res["container_id"]
        instance.internal_port = container_res["assigned_port"]
        instance.status = "running"
        db.commit()

        # Audit log
        db.add(
            AuditLog(
                timestamp=now,
                user_id=current_user.id,
                session_id=instance.id,
                event_type="INSTANCE_START",
                severity="INFO",
                details_json={
                    "challenge_id": chal.id,
                    "driver": container_res.get("driver"),
                    "duration_minutes": duration_minutes,
                },
            )
        )
        db.commit()

        return {
            "id": instance.id,
            "challenge_id": chal.id,
            "status": instance.status,
            "proxy_path": f"/session/{instance.id}/?access_token={instance.proxy_token}&token={instance.proxy_token}",
            "environment_type": chal.environment_type,
            "time_remaining_seconds": int((expires_at - now).total_seconds()),
            "message": "Challenge environment initialized successfully.",
        }

    except Exception as e:
        instance.status = "error"
        instance.error_message = str(e)
        db.commit()
        raise HTTPException(
            status_code=500, detail=f"Failed to start challenge container: {e}"
        )


@router.get("/api/instances/{session_id}/status")
def get_instance_status(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get status and remaining time for a student's session."""
    inst = (
        db.query(ChallengeInstance)
        .filter(
            ChallengeInstance.id == session_id,
            ChallengeInstance.user_id == current_user.id,
        )
        .first()
    )

    if not inst:
        raise HTTPException(status_code=404, detail="Instance session not found.")

    now = datetime.utcnow()
    time_remaining = max(0, int((inst.expires_at - now).total_seconds()))

    return {
        "id": inst.id,
        "challenge_id": inst.challenge_id,
        "status": inst.status,
        "proxy_path": f"/session/{inst.id}/?access_token={inst.proxy_token}&token={inst.proxy_token}",
        "time_remaining_seconds": time_remaining,
    }


@router.post("/api/instances/{session_id}/stop")
async def stop_instance(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Stop and destroy a student's running environment."""
    success = await janitor_service.terminate_session(
        session_id, db, current_user.id, "USER_STOPPED"
    )
    if not success:
        raise HTTPException(
            status_code=404, detail="Session not found or already stopped."
        )
    return {"message": "Environment stopped and isolated resources reclaimed."}


@router.post("/api/instances/{session_id}/reset")
async def reset_instance(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Reset a student's environment back to a fresh starting state."""
    inst = (
        db.query(ChallengeInstance)
        .filter(
            ChallengeInstance.id == session_id,
            ChallengeInstance.user_id == current_user.id,
        )
        .first()
    )

    if not inst:
        raise HTTPException(status_code=404, detail="Session not found.")

    challenge_id = inst.challenge_id
    await janitor_service.terminate_session(
        session_id, db, current_user.id, "USER_RESET"
    )

    # Start fresh instance
    return await start_challenge_instance(challenge_id, current_user, db)
