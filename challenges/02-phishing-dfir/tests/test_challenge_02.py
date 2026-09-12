from pathlib import Path
import json


def test_challenge_02_solvable():
    eml_file = Path(__file__).parent.parent / "data" / "urgent_invoice.eml"
    dns_file = Path(__file__).parent.parent / "data" / "dns_telemetry.json"

    assert eml_file.exists(), "EML evidence missing"
    assert dns_file.exists(), "DNS telemetry missing"

    with open(dns_file) as f:
        dns_records = json.load(f)

    # Flag exists in correlated DNS telemetry
    flag_entry = next((r for r in dns_records if "FLAG{dmarc_fail_invoice_c2_domain_detected}" in r.get("notes", "")), None)
    assert flag_entry is not None, "Flag missing in DNS telemetry"
