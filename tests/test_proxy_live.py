"""Test verifying reverse proxy HTTP routing without DetachedInstanceError."""

import pytest
from starlette.requests import Request
from starlette.datastructures import Headers, QueryParams
from cyberlab.db.database import SessionLocal
from cyberlab.db.models import ChallengeInstance, User, Challenge
from cyberlab.services.proxy import proxy_service
from cyberlab.core.security import generate_secure_token
from datetime import datetime, timedelta


def test_proxy_session_validation_without_detached_error():
    db = SessionLocal()
    try:
        user = db.query(User).first()
        if not user:
            user = User(
                lms_user_id="test-proxy-user", username="puser", email="p@cyberlab.edu"
            )
            db.add(user)
            db.commit()

        token = generate_secure_token(32)
        inst = ChallengeInstance(
            user_id=user.id,
            challenge_id="01-soc-auth-investigation",
            proxy_token=token,
            internal_port=9099,
            status="running",
            expires_at=datetime.utcnow() + timedelta(minutes=45),
        )
        db.add(inst)
        db.commit()
        session_id = inst.id

        # Verify that _validate_session returns safe detached dict without throwing
        session_info = proxy_service._validate_session(session_id, token)
        assert session_info["internal_port"] == 9099
        assert session_info["environment_type"] == "marimo"
        assert session_info["status"] == "running"
        assert session_info["proxy_token"] == token

        # Verify fallback validation without explicit token (e.g. from internal Marimo subresources)
        session_info_no_tok = proxy_service._validate_session(session_id)
        assert session_info_no_tok["internal_port"] == 9099
        assert session_info_no_tok["proxy_token"] == token

    finally:
        db.close()


def test_proxy_session_validation_rejects_invalid_token():
    db = SessionLocal()
    try:
        user = db.query(User).first()
        inst = ChallengeInstance(
            user_id=user.id,
            challenge_id="01-soc-auth-investigation",
            proxy_token=generate_secure_token(32),
            internal_port=9099,
            status="running",
            expires_at=datetime.utcnow() + timedelta(minutes=45),
        )
        db.add(inst)
        db.commit()

        with pytest.raises(Exception) as exc_info:
            proxy_service._validate_session(inst.id, "wrong-token")
        assert "403" in str(exc_info.value)
    finally:
        db.close()
