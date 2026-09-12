# INCIDENT 0303 — Compromised Linux Server Forensics

## Incident Narrative

During routine network monitoring, an automated alert triggered on production Linux server `web-prod-04` (IP `10.0.3.14`). The host was initiating periodic TCP connections to an unknown external port every 15 minutes.

The forensic response team acquired a triage collection package from the host and staged it in `/workspace/data/`.

## Forensic Artifacts

- `data/var/log/auth.log` — PAM and SSH authentication events.
- `data/home/deploy/.bash_history` — Shell execution history of the deployment account.
- `data/etc/crontab` & `data/etc/cron.d/` — Scheduled tasks and system cron configurations.
- `data/opt/` — Installed applications and local scripts.

## Your Mission

Using the interactive Python Marimo notebook:

1. Reconstruct the attacker's actions from entry to privilege escalation.
2. Determine how the attacker established persistence across system reboots.
3. Locate the hidden reverse shell artifact.
4. Extract the incident flag and submit it to CTFd.

**Flag Format**: `FLAG{...}`
