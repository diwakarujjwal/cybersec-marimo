"""Background cleaner for expired sessions and orphaned containers."""
import asyncio
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from cyberlab.core.config import settings
from cyberlab.db.database import SessionLocal
from cyberlab.db.models import ChallengeInstance, AuditLog
from cyberlab.services.docker_service import container_manager

logger = logging.getLogger("cyberlab.janitor")


class JanitorService:
    """Monitors instance TTLs, idle timeouts, and container reclamation."""

    def __init__(self):
        self._running = False
        self._task = None

    async def start(self):
        """Start the background janitor loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Janitor service started.")

    async def stop(self):
        """Stop the background janitor loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Janitor service stopped.")

    async def _run_loop(self):
        while self._running:
            try:
                await self.cleanup_expired_and_idle()
            except Exception as e:
                logger.error(f"Error in janitor cycle: {e}")
            await asyncio.sleep(settings.JANITOR_INTERVAL_SECONDS)

    async def cleanup_expired_and_idle(self) -> int:
        """Scan and terminate all expired or idle container sessions."""
        cleaned_count = 0
        db: Session = SessionLocal()
        now = datetime.utcnow()
        idle_threshold = now - timedelta(minutes=settings.IDLE_TIMEOUT_MINUTES)

        try:
            # Find active instances
            active_instances = db.query(ChallengeInstance).filter(
                ChallengeInstance.status.in_(["starting", "running"])
            ).all()

            for inst in active_instances:
                is_expired = inst.expires_at <= now
                is_idle = inst.last_heartbeat_at <= idle_threshold

                if is_expired or is_idle:
                    reason = "EXPIRED" if is_expired else "IDLE_TIMEOUT"
                    logger.info(f"Reclaiming instance {inst.id} ({inst.challenge_id}) due to {reason}.")

                    # Terminate container & free port
                    await container_manager.terminate_instance(
                        container_id=inst.container_id or "",
                        session_id=inst.id,
                        port=inst.internal_port,
                    )

                    inst.status = "expired"
                    db.add(
                        AuditLog(
                            timestamp=now,
                            user_id=inst.user_id,
                            session_id=inst.id,
                            event_type=f"INSTANCE_{reason}",
                            severity="INFO",
                            details_json={
                                "challenge_id": inst.challenge_id,
                                "container_id": inst.container_id,
                                "reason": reason,
                            },
                        )
                    )
                    cleaned_count += 1

            db.commit()
        except Exception as e:
            logger.error(f"Database error during janitor cleanup: {e}")
            db.rollback()
        finally:
            db.close()

        return cleaned_count

    async def terminate_session(self, session_id: str, db: Session, user_id: Optional[str] = None, reason: str = "USER_TERMINATED") -> bool:
        """Explicitly terminate a single session."""
        query = db.query(ChallengeInstance).filter(ChallengeInstance.id == session_id)
        if user_id:
            query = query.filter(ChallengeInstance.user_id == user_id)
        inst = query.first()
        if not inst:
            return False

        if inst.status in ["starting", "running"]:
            await container_manager.terminate_instance(
                container_id=inst.container_id or "",
                session_id=inst.id,
                port=inst.internal_port,
            )
            inst.status = "stopped"
            db.add(
                AuditLog(
                    timestamp=datetime.utcnow(),
                    user_id=inst.user_id,
                    session_id=inst.id,
                    event_type=f"INSTANCE_{reason}",
                    severity="INFO",
                    details_json={"challenge_id": inst.challenge_id, "reason": reason},
                )
            )
            db.commit()
            return True
        return False


janitor_service = JanitorService()

