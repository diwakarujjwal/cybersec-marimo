"""Configuration module for CyberLab platform."""

import os
from pathlib import Path
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CHALLENGES_DIR = BASE_DIR / "challenges"


class Settings(BaseModel):
    # Core app settings
    APP_NAME: str = "CyberLab Training Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "cyberlab-super-secret-dev-key-change-in-prod-2026"
    )
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8888"))

    # Paths
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    SANDBOX_DIR: Path = DATA_DIR / ".sandboxes"
    CHALLENGES_DIR: Path = CHALLENGES_DIR
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR}/cyberlab.db")

    # Container & Sandbox Security Configurations
    DOCKER_HOST: str = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    DOCKER_DRIVER: str = os.getenv(
        "DOCKER_DRIVER", "auto"
    )  # "docker", "mock", "process", "auto"
    CONTAINER_CPU_LIMIT: str = os.getenv("CONTAINER_CPU_LIMIT", "0.5")
    CONTAINER_MEMORY_LIMIT: str = os.getenv("CONTAINER_MEMORY_LIMIT", "512m")
    CONTAINER_PIDS_LIMIT: int = int(os.getenv("CONTAINER_PIDS_LIMIT", "100"))
    CONTAINER_READ_ONLY_ROOT: bool = True
    CONTAINER_UID: int = 1000
    CONTAINER_GID: int = 1000
    CONTAINER_DROP_CAPABILITIES: list[str] = ["ALL"]
    CONTAINER_SECURITY_OPT: list[str] = ["no-new-privileges:true"]

    # Lifecycle & Quotas
    DEFAULT_INSTANCE_TTL_MINUTES: int = int(
        os.getenv("DEFAULT_INSTANCE_TTL_MINUTES", "45")
    )
    MAX_INSTANCE_TTL_MINUTES: int = int(os.getenv("MAX_INSTANCE_TTL_MINUTES", "120"))
    IDLE_TIMEOUT_MINUTES: int = int(os.getenv("IDLE_TIMEOUT_MINUTES", "15"))
    MAX_INSTANCES_PER_STUDENT: int = int(os.getenv("MAX_INSTANCES_PER_STUDENT", "1"))
    MAX_GLOBAL_INSTANCES: int = int(os.getenv("MAX_GLOBAL_INSTANCES", "50"))
    JANITOR_INTERVAL_SECONDS: int = int(os.getenv("JANITOR_INTERVAL_SECONDS", "30"))

    # CTFd Integration
    CTFD_URL: str = os.getenv("CTFD_URL", "http://localhost:8000")
    CTFD_API_TOKEN: str = os.getenv("CTFD_API_TOKEN", "")
    ENABLE_EMBEDDED_CTFD_MOCK: bool = (
        os.getenv("ENABLE_EMBEDDED_CTFD_MOCK", "true").lower() == "true"
    )

    # LMS Integration
    LMS_URL: str = os.getenv("LMS_URL", "http://localhost:3000")
    LMS_SHARED_SECRET: str = os.getenv(
        "LMS_SHARED_SECRET", "lms-shared-secret-auth-key"
    )

    # Marimo Runner
    MARIMO_HOST: str = "127.0.0.1"
    PORT_RANGE_START: int = 9000
    PORT_RANGE_END: int = 9999


settings = Settings()

# Ensure data directory exists
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
