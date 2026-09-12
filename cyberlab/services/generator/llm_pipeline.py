"""LLM-driven pipeline for converting video transcripts into procedural CTF challenges."""
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
import httpx

from cyberlab.core.config import settings
from cyberlab.services.generator.template_base import BaseChallengeTemplate
from cyberlab.services.generator.templates import TEMPLATE_REGISTRY, get_template
from cyberlab.services.ctfd_client import ctfd_client

logger = logging.getLogger("cyberlab.generator")


class TranscriptChallengeGenerator:
    """
    Ingests training lecture / walkthrough video transcripts, extracts learning
    objectives, matches with human-crafted challenge templates, fills parameter slots,
    synthesizes randomized sandboxes, and synchronizes to CTFd with hint locking.
    """

    def __init__(self, gemini_api_key: str = "", openai_api_key: str = ""):
        self.gemini_api_key = gemini_api_key or settings.GEMINI_API_KEY
        self.openai_api_key = openai_api_key or settings.OPENAI_API_KEY
        self.model = settings.LLM_MODEL

    async def extract_objectives(self, transcript_text: str) -> Dict[str, Any]:
        """
        Analyze video transcript to identify key attack techniques, learning objectives,
        and target cybersecurity domain.
        """
        prompt = (
            "You are an expert cybersecurity educator and curriculum architect. "
            "Analyze the following lecture/walkthrough video transcript and extract:\n"
            "1. Primary domain (e.g. 'SOC Investigation', 'DFIR Investigation', 'Threat Hunting', 'Web Security')\n"
            "2. 3-4 specific hands-on learning objectives\n"
            "3. Key attacker techniques or MITRE ATT&CK identifiers (e.g., 'T1110.001', 'T1566.001')\n"
            "4. Technical keywords (e.g., 'Event 4625', 'brute force', 'SPF', 'DMARC', 'PowerShell')\n"
            "5. Recommended difficulty level ('Beginner', 'Intermediate', 'Advanced')\n\n"
            "Return strictly valid JSON with keys: 'domain', 'objectives', 'mitre_techniques', 'keywords', 'difficulty'.\n\n"
            f"Transcript:\n{transcript_text[:4000]}"
        )

        # 1. Attempt Gemini API if key is available
        if self.gemini_api_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.gemini_api_key}"
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
                        if match:
                            return json.loads(match.group(0))
            except Exception as e:
                logger.warning(f"Gemini API extraction failed: {e}. Falling back to heuristic parser.")

        # 2. Rule-based / NLP heuristic fallback (offline & reliable)
        text_lower = transcript_text.lower()
        if any(w in text_lower for w in ["phish", "email", "eml", "dmarc", "spf", "dkim", "invoice", "macro"]):
            return {
                "domain": "DFIR Investigation",
                "objectives": [
                    "Evaluate SPF, DKIM, and DMARC mail authentication failures",
                    "Carve and deobfuscate malicious VBA attachment macro",
                    "Correlate C2 beaconing in DNS telemetry to extract flag",
                ],
                "mitre_techniques": ["T1566.001", "T1204.002", "T1059.005", "T1071.001"],
                "keywords": ["dmarc", "spf", "eml", "powershell", "dns", "invoice"],
                "difficulty": "Intermediate",
            }
        else:
            # Default to SOC authentication investigation
            return {
                "domain": "SOC Investigation",
                "objectives": [
                    "Isolate external brute-force authentication spikes",
                    "Identify compromised internal user accounts during off-hours",
                    "Trace Living-off-the-Land post-exploitation commands",
                ],
                "mitre_techniques": ["T1110.001", "T1078.002", "T1105"],
                "keywords": ["event 4625", "event 4624", "brute force", "certutil", "kerberos"],
                "difficulty": "Beginner",
            }

    def match_template(self, objectives_meta: Dict[str, Any]) -> BaseChallengeTemplate:
        """Match extracted objectives and domain to a human-authored challenge template."""
        domain = objectives_meta.get("domain", "").lower()
        keywords = [k.lower() for k in objectives_meta.get("keywords", [])]

        if "dfir" in domain or any(k in ["phish", "email", "dmarc", "eml"] for k in keywords):
            return get_template("phishing-dfir")

        # Default to SOC authentication triage
        return get_template("soc-auth-investigation")

    async def fill_slots(
        self,
        template: BaseChallengeTemplate,
        objectives_meta: Dict[str, Any],
        student_seed: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Fill template parameter slots. Seeds deterministic randomization per student
        so every generation produces different IP addresses, usernames, and flags.
        """
        return template.generate_random_slots(seed=student_seed)

    async def generate_and_deploy(
        self,
        transcript_text: str,
        output_dir: Path,
        student_id: Optional[str] = None,
        sync_to_ctfd: bool = True,
    ) -> Dict[str, Any]:
        """
        End-to-end generator pipeline:
        1. Transcript -> Extracted Objectives
        2. Objectives -> Selected Template
        3. Template -> Slot Filling (Randomized per student seed)
        4. Slot Values -> Synthetic Artifacts (Logs, EML, PCAPs) & Marimo Notebook
        5. Deployment -> Synchronize to CTFd with hint locking
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Extract objectives
        objectives_meta = await self.extract_objectives(transcript_text)

        # 2. Match template
        template = self.match_template(objectives_meta)

        # 3. Fill slots with student seed for anti-cheat uniqueness
        slots = await self.fill_slots(template, objectives_meta, student_seed=student_id)

        # 4. Build challenge package
        pkg = template.build_challenge_package(slots, output_dir)
        manifest = pkg["manifest"]

        # 5. Sync challenge and locked hints to CTFd
        ctfd_id = None
        if sync_to_ctfd:
            ctfd_id = await ctfd_client.register_challenge(manifest)
            manifest["ctfd_id"] = ctfd_id

        return {
            "challenge_id": pkg["id"],
            "title": manifest["title"],
            "category": manifest["category"],
            "difficulty": manifest["difficulty"],
            "points": manifest["points"],
            "flag": manifest["flag"],
            "hints_count": len(manifest["hints"]),
            "hints": manifest["hints"],
            "objectives": manifest["objectives"],
            "ctfd_id": ctfd_id,
            "package_path": str(pkg["directory"]),
            "slots": slots,
            "objectives_meta": objectives_meta,
        }


transcript_generator = TranscriptChallengeGenerator()
