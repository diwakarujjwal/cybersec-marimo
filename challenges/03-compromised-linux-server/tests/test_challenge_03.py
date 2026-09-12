from pathlib import Path


def test_challenge_03_solvable():
    cron_file = Path(__file__).parent.parent / "data" / "etc" / "cron.d" / "cert-sync"
    script_file = Path(__file__).parent.parent / "data" / "opt" / "cert-tools" / ".sync.sh"

    assert cron_file.exists(), "Cron artifact missing"
    assert script_file.exists(), "Backdoor script missing"

    content = script_file.read_text()
    assert "FLAG{crontab_reverse_shell_persisted_victim}" in content
