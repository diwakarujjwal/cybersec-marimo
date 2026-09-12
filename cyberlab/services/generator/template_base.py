"""Base classes and interfaces for procedural challenge templates."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional
import hashlib
import random
import yaml


class BaseChallengeTemplate(ABC):
    """
    Abstract base class for human-authored CTF challenge templates.
    Ensures deterministic slot filling, dynamic artifact synthesis,
    flag computation, and hint generation.
    """

    template_id: str
    title: str
    category: str
    difficulty: str
    base_points: int = 100
    duration_minutes: int = 45
    competency_id: str
    competency_weight: float = 1.0

    @abstractmethod
    def get_slot_schema(self) -> Dict[str, Dict[str, Any]]:
        """Return schema of required slots with description and type."""
        pass

    @abstractmethod
    def generate_random_slots(
        self, seed: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate realistic randomized parameters for this challenge template."""
        pass

    @abstractmethod
    def compute_flag(self, slots: Dict[str, Any]) -> str:
        """Deterministically compute the expected flag string for given slots."""
        pass

    @abstractmethod
    def generate_hints(self, slots: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate tiered hints with point penalties.
        These are registered strictly in CTFd and locked from the student.
        """
        pass

    @abstractmethod
    def generate_objectives(self, slots: Dict[str, Any]) -> List[str]:
        """Generate investigation objectives tailored to the specific slots."""
        pass

    @abstractmethod
    def generate_scenario_description(self, slots: Dict[str, Any]) -> str:
        """Generate scenario narrative formatted in Markdown."""
        pass

    @abstractmethod
    def synthesize_artifacts(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Dict[str, Path]:
        """
        Synthesize evidence and telemetry files (e.g. JSON logs, EML, PCAPs)
        into output_dir/data.
        """
        pass

    @abstractmethod
    def generate_notebook(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Path:
        """Generate the Marimo interactive analyst notebook in output_dir/marimo."""
        pass

    def build_challenge_package(
        self,
        slots: Dict[str, Any],
        output_dir: Path,
        challenge_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Produce a complete, self-contained challenge package ready to be deployed
        and synchronized to CTFd.
        """
        chal_id = challenge_id or f"{self.template_id}-{slots.get('seed_hash', 'auto')[:8]}"
        pkg_dir = output_dir / chal_id
        pkg_dir.mkdir(parents=True, exist_ok=True)

        flag = self.compute_flag(slots)
        hints = self.generate_hints(slots)
        objectives = self.generate_objectives(slots)
        scenario_md = self.generate_scenario_description(slots)

        # 1. Write challenge.yaml
        manifest = {
            "id": chal_id,
            "title": f"{self.title}: {slots.get('incident_codename', 'Operation Zero')}",
            "category": self.category,
            "difficulty": self.difficulty,
            "points": self.base_points,
            "duration_minutes": self.duration_minutes,
            "competency_id": self.competency_id,
            "competency_weight": self.competency_weight,
            "container": {
                "type": "marimo",
                "image": "cyberlab/sandbox:latest",
                "cpu_limit": "0.5",
                "memory_limit": "512M",
                "pids_limit": 100,
                "read_only_root": True,
                "network": "internal",
            },
            "flag": flag,
            "hints": hints,
            "objectives": objectives,
            "scenario_md": scenario_md,
            "slots": slots,
        }

        with open(pkg_dir / "challenge.yaml", "w") as f:
            yaml.safe_dump(manifest, f, sort_keys=False)

        # 2. Synthesize data artifacts
        data_files = self.synthesize_artifacts(slots, pkg_dir)

        # 3. Generate Marimo notebook
        nb_path = self.generate_notebook(slots, pkg_dir)

        return {
            "id": chal_id,
            "manifest": manifest,
            "directory": pkg_dir,
            "data_files": data_files,
            "notebook_path": nb_path,
        }
