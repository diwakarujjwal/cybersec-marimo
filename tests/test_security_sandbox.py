"""Tests verifying the container security sandbox parameters and threat model enforcement."""
import pytest
from cyberlab.services.docker_service import ContainerSecurityProfile, ContainerManager
from cyberlab.core.security import sanitize_container_view


def test_container_security_profile_defaults():
    """Ensure that default container security parameters strictly match our threat model."""
    profile = ContainerSecurityProfile()
    data = profile.to_dict()

    # Non-root user
    assert data["uid"] == 1000
    assert data["gid"] == 1000

    # Read-only root filesystem
    assert data["read_only_root"] is True

    # Drop all capabilities
    assert data["drop_capabilities"] == ["ALL"]

    # Privilege escalation banned
    assert data["no_new_privileges"] is True

    # Resource caps enforced
    assert data["cpu_limit"] == "0.5"
    assert data["memory_limit"] == "512m"
    assert data["pids_limit"] == 100

    # Strict tmpfs restrictions
    assert "/tmp" in data["tmpfs_mounts"]
    assert "noexec" in data["tmpfs_mounts"]["/tmp"]


def test_student_container_view_sanitization():
    """Ensure internal container IDs, daemon sockets, and host IPs are never exposed to students."""
    raw_instance = {
        "id": "sess-12345",
        "challenge_id": "01-soc-auth",
        "container_id": "sha256:abcd9876543210fedcba",
        "internal_port": 9005,
        "internal_ip": "172.18.0.4",
        "docker_socket": "/var/run/docker.sock",
        "status": "running",
        "proxy_path": "/session/sess-12345/?token=xyz",
        "time_remaining_seconds": 2400,
        "environment_type": "marimo",
    }

    sanitized = sanitize_container_view(raw_instance)

    # Allowed student fields
    assert sanitized["id"] == "sess-12345"
    assert sanitized["proxy_path"] == "/session/sess-12345/?token=xyz"
    assert sanitized["status"] == "running"

    # Blocked sensitive infrastructure fields
    assert "container_id" not in sanitized
    assert "internal_port" not in sanitized
    assert "internal_ip" not in sanitized
    assert "docker_socket" not in sanitized

