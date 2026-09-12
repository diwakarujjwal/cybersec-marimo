"""SQLAlchemy ORM models for CyberLab."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from cyberlab.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    lms_user_id = Column(String(128), unique=True, index=True, nullable=False)
    username = Column(String(64), index=True, nullable=False)
    email = Column(String(255), nullable=False)
    role = Column(String(32), default="student", nullable=False)  # student, instructor, admin
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    instances = relationship("ChallengeInstance", back_populates="user", cascade="all, delete-orphan")
    submissions = relationship("Submission", back_populates="user", cascade="all, delete-orphan")
    competencies = relationship("UserCompetency", back_populates="user", cascade="all, delete-orphan")


class Competency(Base):
    __tablename__ = "competencies"

    id = Column(String(64), primary_key=True)  # e.g., soc_investigation
    name = Column(String(128), nullable=False)
    description = Column(Text, default="")

    challenges = relationship("Challenge", back_populates="competency")


class UserCompetency(Base):
    __tablename__ = "user_competencies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), index=True, nullable=False)
    competency_id = Column(String(64), ForeignKey("competencies.id"), index=True, nullable=False)
    score_pct = Column(Float, default=0.0)
    challenges_completed = Column(Integer, default=0)
    last_updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="competencies")
    competency = relationship("Competency")


class Challenge(Base):
    __tablename__ = "challenges"

    id = Column(String(64), primary_key=True)  # slug id, e.g., soc-auth-investigation
    ctfd_id = Column(Integer, nullable=True)  # Mapped CTFd challenge ID
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    difficulty = Column(String(32), default="Beginner")
    scenario_md = Column(Text, default="")
    objectives_json = Column(JSON, default=list)
    points = Column(Integer, default=100)
    duration_minutes = Column(Integer, default=45)
    competency_id = Column(String(64), ForeignKey("competencies.id"), nullable=True)
    competency_weight = Column(Float, default=1.0)
    environment_type = Column(String(32), default="marimo")  # marimo, web_app, hybrid
    container_spec = Column(JSON, default=dict)
    flag = Column(String(255), nullable=False)
    hints = Column(JSON, default=list)
    enabled = Column(Boolean, default=True)

    competency = relationship("Competency", back_populates="challenges")
    instances = relationship("ChallengeInstance", back_populates="challenge", cascade="all, delete-orphan")
    submissions = relationship("Submission", back_populates="challenge", cascade="all, delete-orphan")


class ChallengeInstance(Base):
    __tablename__ = "challenge_instances"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # session_id
    user_id = Column(String(36), ForeignKey("users.id"), index=True, nullable=False)
    challenge_id = Column(String(64), ForeignKey("challenges.id"), index=True, nullable=False)
    container_id = Column(String(128), nullable=True)
    proxy_token = Column(String(128), unique=True, index=True, nullable=False)
    internal_port = Column(Integer, nullable=False)
    status = Column(String(32), default="starting")  # starting, running, stopped, expired, error
    started_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_heartbeat_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text, nullable=True)

    user = relationship("User", back_populates="instances")
    challenge = relationship("Challenge", back_populates="instances")


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), index=True, nullable=False)
    challenge_id = Column(String(64), ForeignKey("challenges.id"), index=True, nullable=False)
    submitted_flag = Column(String(255), nullable=False)
    is_correct = Column(Boolean, default=False)
    points_awarded = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="submissions")
    challenge = relationship("Challenge", back_populates="submissions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String(36), nullable=True)
    session_id = Column(String(36), nullable=True)
    event_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), default="INFO")  # INFO, WARN, ALERT, ERROR
    details_json = Column(JSON, default=dict)

