"""Standard challenge package loader and synchronizer."""
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cyberlab.core.config import settings
from cyberlab.db.models import Challenge
from cyberlab.services.ctfd_client import ctfd_client

logger = logging.getLogger("cyberlab.challenges")


class HintConfig(BaseModel):
    id: int
    content: str
    penalty: int = 10


class ContainerConfig(BaseModel):
    type: str = "marimo"  # "marimo", "web_app", "hybrid"
    image: Optional[str] = None
    cpu_limit: str = "0.5"
    memory_limit: str = "512M"
    pids_limit: int = 100
    read_only_root: bool = True
    network: str = "internal"


class ChallengeManifest(BaseModel):
    id: str
    title: str
    category: str
    difficulty: str = "Beginner"
    points: int = 100
    duration_minutes: int = 45
    competency_id: Optional[str] = None
    competency_weight: float = 1.0
    container: ContainerConfig = Field(default_factory=ContainerConfig)
    flag: str
    hints: List[HintConfig] = Field(default_factory=list)
    objectives: List[str] = Field(default_factory=list)


class ChallengeLoader:
    """Discovers, parses, validates, and synchronizes challenge packages."""

    @staticmethod
    def load_challenge_from_dir(dir_path: Path) -> Optional[Dict[str, Any]]:
        yaml_file = dir_path / "challenge.yaml"
        if not yaml_file.exists():
            return None

        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)

            manifest = ChallengeManifest(**raw_data)

            # Read README.md if available for full markdown scenario
            scenario_md = ""
            readme_file = dir_path / "README.md"
            if readme_file.exists():
                with open(readme_file, "r", encoding="utf-8") as f:
                    scenario_md = f.read()

            return {
                "manifest": manifest,
                "scenario_md": scenario_md,
                "path": dir_path,
            }
        except Exception as e:
            logger.error(f"Failed parsing challenge manifest in {dir_path}: {e}")
            return None

    @classmethod
    def discover_all(cls, challenges_root: Optional[Path] = None) -> List[Dict[str, Any]]:
        root = challenges_root or settings.CHALLENGES_DIR
        root.mkdir(parents=True, exist_ok=True)
        challenges = []
        for item in sorted(root.iterdir()):
            if item.is_dir():
                chal = cls.load_challenge_from_dir(item)
                if chal:
                    challenges.append(chal)
        return challenges

    @classmethod
    async def sync_to_db_and_ctfd(cls, db: Session, challenges_root: Optional[Path] = None) -> int:
        """Synchronize all discovered challenges into the SQL database and CTFd backend."""
        discovered = cls.discover_all(challenges_root)
        count = 0
        for item in discovered:
            m: ChallengeManifest = item["manifest"]
            scenario_md = item["scenario_md"]

            # Check if challenge already registered in DB
            db_chal = db.query(Challenge).filter(Challenge.id == m.id).first()

            # Register with CTFd
            ctfd_id = await ctfd_client.register_challenge({
                "id": m.id,
                "title": m.title,
                "category": m.category,
                "points": m.points,
                "flag": m.flag,
                "hints": [h.model_dump() for h in m.hints],
                "scenario_md": scenario_md,
            })

            if not db_chal:
                db_chal = Challenge(
                    id=m.id,
                    ctfd_id=ctfd_id,
                    title=m.title,
                    category=m.category,
                    difficulty=m.difficulty,
                    scenario_md=scenario_md,
                    objectives_json=m.objectives,
                    points=m.points,
                    duration_minutes=m.duration_minutes,
                    competency_id=m.competency_id,
                    competency_weight=m.competency_weight,
                    environment_type=m.container.type,
                    container_spec=m.container.model_dump(),
                    flag=m.flag,
                    hints=[h.model_dump() for h in m.hints],
                    enabled=True,
                )
                db.add(db_chal)
            else:
                db_chal.ctfd_id = ctfd_id
                db_chal.title = m.title
                db_chal.category = m.category
                db_chal.difficulty = m.difficulty
                db_chal.scenario_md = scenario_md
                db_chal.objectives_json = m.objectives
                db_chal.points = m.points
                db_chal.duration_minutes = m.duration_minutes
                db_chal.competency_id = m.competency_id
                db_chal.competency_weight = m.competency_weight
                db_chal.environment_type = m.container.type
                db_chal.container_spec = m.container.model_dump()
                db_chal.flag = m.flag
                db_chal.hints = [h.model_dump() for h in m.hints]

            count += 1

        db.commit()
        return count


challenge_loader = ChallengeLoader()
