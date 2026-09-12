"""Unit and integration tests for procedural CTF challenge generator & CTFd hint locking."""
import pytest
import tempfile
from pathlib import Path
import json

from cyberlab.services.generator.templates import get_template, list_templates
from cyberlab.services.generator.templates.soc_auth_template import SocAuthTemplate
from cyberlab.services.generator.templates.phishing_dfir_template import PhishingDfirTemplate
from cyberlab.services.generator.llm_pipeline import transcript_generator
from cyberlab.services.ctfd_client import ctfd_client


def test_template_registry_and_schemas():
    """Verify template registry discovers templates and schemas are complete."""
    templates = list_templates()
    assert len(templates) >= 2
    ids = {t["id"] for t in templates}
    assert "soc-auth-investigation" in ids
    assert "phishing-dfir" in ids

    soc_tpl = get_template("soc-auth-investigation")
    schema = soc_tpl.get_slot_schema()
    assert "attacker_ip" in schema
    assert "victim_account" in schema
    assert "lolbin_tool" in schema


def test_anti_cheat_seed_randomization():
    """Verify that different student seeds produce completely different flags and slots."""
    soc_tpl = SocAuthTemplate()
    slots_alice = soc_tpl.generate_random_slots(seed="student_alice_001")
    slots_bob = soc_tpl.generate_random_slots(seed="student_bob_002")

    flag_alice = soc_tpl.compute_flag(slots_alice)
    flag_bob = soc_tpl.compute_flag(slots_bob)

    # Anti-cheat: different students must not share the same flag or attacker IP
    assert flag_alice != flag_bob
    assert slots_alice["flag_nonce"] != slots_bob["flag_nonce"]

    # Determinism: same student seed reproduces identical slots and flag
    slots_alice_repeat = soc_tpl.generate_random_slots(seed="student_alice_001")
    assert soc_tpl.compute_flag(slots_alice_repeat) == flag_alice


def test_soc_artifact_synthesis():
    """Verify synthetic Windows event telemetry is generated with embedded flag."""
    soc_tpl = SocAuthTemplate()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        slots = soc_tpl.generate_random_slots(seed="test_session_123")
        expected_flag = soc_tpl.compute_flag(slots)

        artifacts = soc_tpl.synthesize_artifacts(slots, tmp_path)
        assert "auth_events.json" in artifacts
        auth_file = artifacts["auth_events.json"]
        assert auth_file.exists()

        with open(auth_file) as f:
            events = json.load(f)

        assert len(events) >= 800

        # Verify brute force spike exists for the randomized attacker IP
        attacker_ip = slots["attacker_ip"]
        attacker_fails = [e for e in events if e.get("source_ip") == attacker_ip and e.get("status") == "FAILURE"]
        assert len(attacker_fails) >= 200

        # Verify command line execution contains the randomized flag
        commands = [e.get("command_line", "") for e in events if "command_line" in e]
        flag_in_cmd = any(expected_flag in cmd for cmd in commands)
        assert flag_in_cmd, f"Flag {expected_flag} was not found in generated command telemetry."


def test_phishing_artifact_synthesis():
    """Verify phishing email and DNS telemetry generation with dynamic C2 flag."""
    phish_tpl = PhishingDfirTemplate()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        slots = phish_tpl.generate_random_slots(seed="phish_seed_456")
        expected_flag = phish_tpl.compute_flag(slots)

        artifacts = phish_tpl.synthesize_artifacts(slots, tmp_path)
        assert "urgent_invoice.eml" in artifacts
        assert "dns_telemetry.json" in artifacts

        eml_content = artifacts["urgent_invoice.eml"].read_text(encoding="utf-8")
        assert "dmarc=fail" in eml_content
        assert slots["sender_domain"] in eml_content

        with open(artifacts["dns_telemetry.json"]) as f:
            dns_data = json.load(f)

        # Flag is in TXT record note
        txt_records = [r for r in dns_data if r.get("record_type") == "TXT"]
        assert any(expected_flag in r.get("notes", "") for r in txt_records)


@pytest.mark.anyio
async def test_transcript_extraction_and_pipeline():
    """Verify transcript ingestion, template matching, and package creation."""
    soc_transcript = """
    In today's lecture on Security Operations, we are analyzing Event ID 4625.
    When an external attacker conducts a brute force attack or password spray,
    SIEM triggers a high severity alert. Notice the attacker IP generating hundreds of
    failed NTLM authentication attempts, followed by a 4624 success for the domain administrator.
    Finally, the attacker invokes certutil.exe to download their second-stage pivot payload.
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        result = await transcript_generator.generate_and_deploy(
            transcript_text=soc_transcript,
            output_dir=tmp_path,
            student_id="student_carol_789",
            sync_to_ctfd=True,
        )

        assert result["category"] == "SOC Investigation"
        assert result["hints_count"] == 3
        assert len(result["objectives"]) >= 2
        assert "FLAG{" in result["flag"]

        # Verify hint locking: hints have point penalties
        for h in result["hints"]:
            assert h["penalty"] > 0
            assert "content" in h

        # Verify challenge package generated on disk
        pkg_dir = Path(result["package_path"])
        assert (pkg_dir / "challenge.yaml").exists()
        assert (pkg_dir / "data" / "auth_events.json").exists()
        assert (pkg_dir / "marimo" / "challenge.py").exists()


@pytest.mark.anyio
async def test_ctfd_hint_locking_and_penalties():
    """Verify that unlocked hints penalize student score on CTFd flag submission."""
    chal_id = "test-hint-lock-chal"
    hints = [
        {"id": 1, "content": "Look at the IP column.", "penalty": 15},
        {"id": 2, "content": "Inspect the certutil command line.", "penalty": 25},
    ]
    manifest = {
        "id": chal_id,
        "title": "SOC Test",
        "category": "SOC",
        "points": 100,
        "flag": "FLAG{verified_ctfd_solve_2026}",
        "hints": hints,
    }

    # Register in CTFd
    await ctfd_client.register_challenge(manifest)

    student_id = "student_dave_999"

    # 1. Unlock Hint 1 (-15 pts)
    success, content, penalty = await ctfd_client.unlock_hint(chal_id, 1, student_id, hints)
    assert success is True
    assert penalty == 15
    assert "Look at the IP" in content

    # 2. Submit correct flag -> should receive 100 - 15 = 85 points
    is_correct, awarded, msg = await ctfd_client.submit_flag(
        challenge_id=chal_id,
        submitted_flag="FLAG{verified_ctfd_solve_2026}",
        user_id=student_id,
        expected_flag="FLAG{verified_ctfd_solve_2026}",
        points=100,
    )
    assert is_correct is True
    assert awarded == 85  # 100 - 15 = 85 pts!
