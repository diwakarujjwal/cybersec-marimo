"""Security utilities, token issuance, and isolation validations."""
import hmac
import hashlib
import secrets
import time
from typing import Optional, Dict, Any
from cyberlab.core.config import settings


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def timing_safe_flag_check(submitted_flag: str, target_flag: str) -> bool:
    """Perform timing-safe comparison between submitted flag and correct flag."""
    if not submitted_flag or not target_flag:
        return False
    return hmac.compare_digest(submitted_flag.strip(), target_flag.strip())


def create_session_token(user_id: str, role: str, expires_in_seconds: int = 86400) -> str:
    """Create a tamper-proof HMAC signed token for session authentication."""
    expiry = int(time.time()) + expires_in_seconds
    payload = f"{user_id}:{role}:{expiry}"
    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{payload}:{signature}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify HMAC signed token. Returns user payload or None if invalid/expired."""
    try:
        parts = token.split(":")
        if len(parts) != 4:
            return None
        user_id, role, expiry_str, signature = parts
        expiry = int(expiry_str)
        if time.time() > expiry:
            return None

        payload = f"{user_id}:{role}:{expiry_str}"
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        return {"user_id": user_id, "role": role, "expires_at": expiry}
    except Exception:
        return None


def sanitize_container_view(instance_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize instance details for student-facing APIs.
    Strips internal container IDs, host bindings, internal IP addresses, and daemon configs.
    """
    allowed_keys = {
        "id", "challenge_id", "status", "started_at", "expires_at",
        "proxy_path", "time_remaining_seconds", "environment_type"
    }
    return {k: v for k, v in instance_data.items() if k in allowed_keys}

