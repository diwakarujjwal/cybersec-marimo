"""Tests verifying container instance TTL expiration and janitor cleanup."""
import asyncio
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberlab.db.database import Base
from cyberlab.db.models import User, ChallengeInstance
from cyberlab.services.janitor import janitor_service
from cyberlab.services.docker_service import container_manager


def test_janitor_expiration():
    async def run():
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = TestingSessionLocal()

        user = User(lms_user_id="test-exp-user", username="tester", email="test@test.com")
        db.add(user)
        db.commit()

        now = datetime.utcnow()
        past = now - timedelta(minutes=50)

        port = container_manager.allocate_port()

        inst = ChallengeInstance(
            id="expired-sess-1",
            user_id=user.id,
            challenge_id="01-soc-auth-investigation",
            proxy_token="secret_token",
            internal_port=port,
            status="running",
            started_at=past,
            expires_at=past + timedelta(minutes=45),
            last_heartbeat_at=past,
        )
        db.add(inst)
        db.commit()

        success = await janitor_service.terminate_session("expired-sess-1", db, reason="TEST_CLEANUP")
        assert success is True

        updated_inst = db.query(ChallengeInstance).filter(ChallengeInstance.id == "expired-sess-1").first()
        assert updated_inst.status == "stopped"

        assert port not in container_manager._used_ports
        db.close()

    asyncio.run(run())

