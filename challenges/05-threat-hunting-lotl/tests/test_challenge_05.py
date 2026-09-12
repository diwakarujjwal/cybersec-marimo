import csv
import base64
from pathlib import Path


def test_challenge_05_solvable():
    proc_file = Path(__file__).parent.parent / "data" / "sysmon_processes.csv"
    dns_file = Path(__file__).parent.parent / "data" / "dns_queries.csv"

    assert proc_file.exists(), "Sysmon process telemetry missing"
    assert dns_file.exists(), "DNS query telemetry missing"

    with open(dns_file, newline="") as f:
        reader = csv.DictReader(f)
        dns_rows = list(reader)

    exfil_query = next((r["query_name"] for r in dns_rows if "exfil-payload" in r["query_name"]), None)
    assert exfil_query is not None, "Exfil payload query missing"

    b64_part = exfil_query.split(".")[1]
    padded = b64_part + "=" * (-len(b64_part) % 4)
    flag = base64.urlsafe_b64decode(padded).decode()
    assert flag == "FLAG{dns_tunneling_data_exfil_uncovered}"
