import json
from pathlib import Path


def test_challenge_01_solvable():
    data_path = Path(__file__).parent.parent / "data" / "auth_events.json"
    assert data_path.exists(), "Dataset missing"

    with open(data_path) as f:
        events = json.load(f)

    # Verify brute force exists
    failures = [e for e in events if e.get("status") == "FAILURE"]
    assert len(failures) >= 200

    # Verify pivot command and flag exist
    commands = [e.get("command_line", "") for e in events if "command_line" in e]
    flag = next((cmd for cmd in commands if "FLAG{brute_force_pivot_admin_2026}" in cmd), None)
    assert flag is not None, "Flag not found in telemetry"
