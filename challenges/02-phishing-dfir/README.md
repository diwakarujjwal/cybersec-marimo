# INCIDENT 0202 — Executive Spearphish & Invoice Fraud

## Incident Scenario

A suspicious email bypassed the spam quarantine and landed in the inbox of an executive assistant in the finance department. The email claims to be an overdue invoice notice with an urgent wire payment instruction.

Shortly after receipt, perimeter firewalls detected outbound DNS queries matching suspicious domains.

## Evidence Available

Located in `/workspace/data/`:

1. `urgent_invoice.eml` — Raw RFC 822 email file with MIME attachments.
2. `dns_telemetry.json` — Internal recursive DNS resolver logs from that morning.

## Your Mission

Using your interactive Python Marimo notebook:

1. Parse the email headers and identify evidence of domain spoofing and DMARC failure.
2. Extract the weaponized attachment and compute its SHA256 hash.
3. Identify the malicious Command & Control (C2) domain queried by the victim workstation.
4. Retrieve the investigation flag embedded in the forensic artifacts.

**Flag Format**: `FLAG{...}`
