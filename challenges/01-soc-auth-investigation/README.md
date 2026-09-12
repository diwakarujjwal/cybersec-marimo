# INCIDENT 0101 — Operation NightShift

## Incident Briefing

At 03:14 UTC, the Security Operations Center (SOC) was alerted to an off-hours anomalous logon on `PAYROLL-SRV01` (Internal IP `10.0.4.50`). The server holds sensitive employee compensation records and corporate disbursement authorizations.

The endpoint detection system recorded multiple preceding failed authentication attempts across several corporate accounts.

## Your Mission

As the on-duty SOC analyst, investigate the authentication telemetry supplied in `/workspace/data/auth_events.json` using the interactive Marimo Python workspace.

### Key Questions to Answer:

1. **Attacker Reconnaissance / Brute Force**: Which external IP generated hundreds of failed login attempts?
2. **Account Breach**: Which internal account was compromised?
3. **Timeline**: At what precise time did the attacker transition from failed attempts to a successful interactive logon?
4. **Post-Exploitation**: What malicious action or pivot did the attacker attempt immediately upon gaining access?

Once you reconstruct the incident, locate the flag recorded in the post-exploitation telemetry and submit it to CTFd.

**Flag Format**: `FLAG{...}`
