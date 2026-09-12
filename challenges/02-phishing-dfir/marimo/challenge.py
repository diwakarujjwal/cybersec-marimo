import marimo

__generated_with = "0.24.1"
app = marimo.App()


@app.cell
def __():
    import base64
    import email
    from email import policy
    import hashlib
    import json
    from pathlib import Path
    import re
    import marimo as mo
    import pandas as pd

    return Path, base64, email, hashlib, json, mo, pd, policy, re


@app.cell
def __(Path, email, hashlib, json, pd, policy):
    # Locate email and DNS telemetry artifacts
    possible_eml_paths = [
        Path("data/urgent_invoice.eml"),
        Path("../data/urgent_invoice.eml"),
        Path("/workspace/data/urgent_invoice.eml"),
        Path("challenges/02-phishing-dfir/data/urgent_invoice.eml"),
    ]
    possible_dns_paths = [
        Path("data/dns_telemetry.json"),
        Path("../data/dns_telemetry.json"),
        Path("/workspace/data/dns_telemetry.json"),
        Path("challenges/02-phishing-dfir/data/dns_telemetry.json"),
    ]
    if "__file__" in globals():
        base_parent = Path(__file__).resolve().parent.parent / "data"
        possible_eml_paths.insert(0, base_parent / "urgent_invoice.eml")
        possible_dns_paths.insert(0, base_parent / "dns_telemetry.json")

    eml_path = next((p for p in possible_eml_paths if p.exists()), None)
    dns_path = next((p for p in possible_dns_paths if p.exists()), None)

    msg = None
    attachments = []
    if eml_path:
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
            if msg.is_multipart():
                for part in msg.iter_attachments():
                    fn = part.get_filename() or "unnamed_attachment"
                    content_bytes = part.get_payload(decode=True) or b""
                    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
                    md5_hash = hashlib.md5(content_bytes).hexdigest()
                    attachments.append(
                        {
                            "filename": fn,
                            "size_bytes": len(content_bytes),
                            "md5": md5_hash,
                            "sha256": sha256_hash,
                            "content_text": content_bytes.decode(
                                "utf-8", errors="ignore"
                            ),
                        }
                    )

    dns_records = []
    if dns_path:
        with open(dns_path) as f:
            dns_records = json.load(f)
    df_dns = pd.DataFrame(dns_records)

    return (
        attachments,
        base_parent,
        df_dns,
        dns_path,
        dns_records,
        eml_path,
        msg,
        possible_dns_paths,
        possible_eml_paths,
    )


@app.cell
def __(mo):
    # Analyst Sidebar: Incident Scope, MITRE ATT&CK & Checklist
    check_headers = mo.ui.checkbox(
        label="1. Audit SPF, DKIM & DMARC alignment", value=False
    )
    check_domain = mo.ui.checkbox(
        label="2. Identify spoofed QuickBooks sender domain", value=False
    )
    check_macro = mo.ui.checkbox(
        label="3. Extract VBA macro & Base64 payload", value=False
    )
    check_decode = mo.ui.checkbox(
        label="4. Decode obfuscated PowerShell command", value=False
    )
    check_c2 = mo.ui.checkbox(
        label="5. Correlate C2 callback domain in DNS telemetry", value=False
    )

    hints = mo.accordion(
        {
            "💡 Hint 1: Email Authentication": mo.md(
                "Inspect **Step 1 (Email Headers)**. Notice `dmarc=fail` and `spf=softfail`. The domain `quickbooks-invoicing-update.com` is typosquatting Intuit QuickBooks."
            ),
            "💡 Hint 2: Macro Analysis": mo.md(
                "Look at **Step 2 (Attachment Forensics)**. The Word document contains an `AutoOpen()` macro executing `powershell -enc <base64>`. Copy that Base64 string into the Decoder Workbench in Step 3."
            ),
            "💡 Hint 3: Decoding & Correlating": mo.md(
                "Decode the Base64 payload in **Step 3** to discover the C2 web request URL and header. Cross-reference the domain in **Step 4 (DNS Telemetry)** to confirm the full beaconing trail."
            ),
        }
    )

    sidebar_content = mo.vstack(
        [
            mo.md("## 🎣 CyberLab DFIR Console"),
            mo.md("**Incident ID**: `INC-0202-SPEARPHISH`"),
            mo.md("**Target Host**: `FIN-WS-1002` (`10.0.2.19`)"),
            mo.md("**Classification**: `TLP:AMBER` | Severity: **HIGH**"),
            mo.md("---"),
            mo.md("### 🎯 Investigation Checklist"),
            check_headers,
            check_domain,
            check_macro,
            check_decode,
            check_c2,
            mo.md("---"),
            mo.md("### 🗺️ MITRE ATT&CK Matrix"),
            mo.md(
                "- **T1566.001**: Spearphishing Attachment\n"
                "- **T1204.002**: User Execution: Malicious File\n"
                "- **T1059.005**: Visual Basic for Applications (VBA)\n"
                "- **T1071.001**: Web Protocols (HTTP C2)"
            ),
            mo.md("---"),
            hints,
        ]
    )

    mo.sidebar(sidebar_content)
    return (
        check_c2,
        check_decode,
        check_domain,
        check_headers,
        check_macro,
        hints,
        sidebar_content,
    )


@app.cell
def __(attachments, df_dns, mo, msg):
    # Header Banner & Stat KPIs
    spf_status = "UNKNOWN"
    dkim_status = "UNKNOWN"
    dmarc_status = "UNKNOWN"
    if msg and msg.get("Authentication-Results"):
        ar = str(msg["Authentication-Results"])
        if "spf=softfail" in ar:
            spf_status = "SOFTFAIL"
        elif "spf=pass" in ar:
            spf_status = "PASS"
        if "dkim=fail" in ar:
            dkim_status = "FAIL"
        elif "dkim=pass" in ar:
            dkim_status = "PASS"
        if "dmarc=fail" in ar:
            dmarc_status = "FAIL (Spoofed)"
        elif "dmarc=pass" in ar:
            dmarc_status = "PASS"

    header_view = mo.vstack(
        [
            mo.md("""
            # 🎣 Incident 0202: Executive Spearphishing & Malicious Macro Triage
            ### Digital Forensics & Incident Response (DFIR) Workbench
            """),
            mo.callout(
                mo.md(
                    "**SOC Escalation Alert**: An employee in Accounts Payable reported an urgent invoice email from an external vendor. Threat Intel feeds flagged an anomalous outbound HTTP beacon from workstation `10.0.2.19` seconds after email receipt. Perform email header inspection, extract the weaponized attachment, reverse the embedded VBA downloader, and reconstruct the C2 callback."
                ),
                kind="warn",
            ),
            mo.hstack(
                [
                    mo.stat(
                        value=dmarc_status,
                        label="DMARC Verdict",
                        caption="Header From Alignment Check",
                        direction="decrease",
                        bordered=True,
                    ),
                    mo.stat(
                        value=dkim_status,
                        label="DKIM Signature",
                        caption="Cryptographic Header Verification",
                        direction="decrease",
                        bordered=True,
                    ),
                    mo.stat(
                        value=spf_status,
                        label="SPF Validation",
                        caption="Sender IP Authorization",
                        direction="decrease",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(attachments)} File(s)",
                        label="Macro Attachments",
                        caption="Extracted from MIME Payload",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(df_dns)} Lookups",
                        label="Correlated DNS Queries",
                        caption="Endpoint: 10.0.2.19",
                        bordered=True,
                    ),
                ],
                justify="start",
                gap=1,
            ),
        ]
    )
    header_view
    return (
        ar,
        dkim_status,
        dmarc_status,
        header_view,
        spf_status,
    )


@app.cell
def __(mo, msg):
    # Step 1: Email Header Forensics
    if msg:
        headers_table = mo.md(f"""
            | Header Field | Evaluated Header Value |
            | :--- | :--- |
            | **From** | `{msg.get('From', '')}` |
            | **To** | `{msg.get('To', '')}` |
            | **Subject** | `{msg.get('Subject', '')}` |
            | **Date** | `{msg.get('Date', '')}` |
            | **Message-ID** | `{msg.get('Message-ID', '')}` |
            | **X-Originating-IP** | `{msg.get('X-Originating-IP', '')}` |
            | **Authentication-Results** | `{msg.get('Authentication-Results', '')}` |
            """)

        spoof_alert = mo.callout(
            mo.md(
                "🚨 **DOMAIN SPOOFING DETECTED**: The sender header claims to be `Intuit Billing Alert` but uses lookalike domain `quickbooks-invoicing-update.com`. SPF returned `softfail` for IP `203.0.113.88` and DMARC evaluated to `fail`."
            ),
            kind="danger",
        )

        body_preview = mo.md(
            f"### ✉️ Email Body Preview\n"
            f"```text\n{msg.get_body(preferencelist=('plain',)).get_content()}\n```"
        )
    else:
        headers_table = mo.md("No email file found.")
        spoof_alert = mo.md("")
        body_preview = mo.md("")

    step1_view = mo.vstack(
        [
            mo.md("## 📨 Step 1: Email Header & Sender Authentication Forensics"),
            spoof_alert,
            mo.md("### 🔍 Raw RFC 822 Email Headers:"),
            headers_table,
            mo.md("---"),
            body_preview,
        ]
    )
    step1_view
    return body_preview, headers_table, spoof_alert, step1_view


@app.cell
def __(attachments, mo):
    # Step 2: Attachment Forensics & Macro Viewer
    if attachments:
        att = attachments[0]
        att_meta_table = mo.md(f"""
            | Document Property | Artifact Detail |
            | :--- | :--- |
            | **Filename** | `{att['filename']}` |
            | **File Size** | `{att['size_bytes']} bytes` |
            | **MD5 Hash** | `{att['md5']}` |
            | **SHA-256 Hash** | `{att['sha256']}` |
            | **MIME Format** | Microsoft Word Macro-Enabled Document (`.docm`) |
            """)

        macro_code_view = mo.md(
            f"### 📜 Decompiled VBA Macro (`{att['filename']}`)\n"
            f"```vb\n{att['content_text']}\n```"
        )
    else:
        att_meta_table = mo.md("No attachments found.")
        macro_code_view = mo.md("")

    step2_view = mo.vstack(
        [
            mo.md("## 📎 Step 2: Extracted Attachment & Decompiled Macro Dissection"),
            mo.md("### 📦 Extracted Document Metadata & Cryptographic Hashes:"),
            att_meta_table,
            mo.md("---"),
            macro_code_view,
        ]
    )
    step2_view
    return att, att_meta_table, macro_code_view, step2_view


@app.cell
def __(attachments, mo, re):
    # Step 3: Decoder UI Controls
    default_b64 = ""
    if attachments:
        vba = attachments[0]["content_text"]
        match = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", vba)
        if match:
            default_b64 = match.group(1)

    decoder_input = mo.ui.text_area(
        value=default_b64,
        placeholder="Paste Base64 payload here...",
        label="Base64 Encoded Payload:",
        full_width=True,
    )

    encoding_mode = mo.ui.dropdown(
        options=["UTF-8 / ASCII", "UTF-16LE (PowerShell -EncodedCommand)"],
        value="UTF-8 / ASCII",
        label="Encoding Format:",
    )

    return decoder_input, default_b64, encoding_mode


@app.cell
def __(base64, decoder_input, encoding_mode, mo):
    # Step 3: Decoder Reactive Computation & View
    decoded_result = ""
    raw_val = decoder_input.value.strip()
    if raw_val:
        try:
            raw_bytes = base64.b64decode(raw_val)
            if encoding_mode.value == "UTF-8 / ASCII":
                decoded_result = raw_bytes.decode("utf-8", errors="replace")
            else:
                decoded_result = raw_bytes.decode("utf-16le", errors="replace")
        except Exception as err:
            decoded_result = f"Decoding error: {err}"

    step3_view = mo.vstack(
        [
            mo.md("## 🔬 Step 3: Interactive DFIR Decoder Tool"),
            mo.md(
                "Decode PowerShell `-enc` / `-EncodedCommand` parameters or suspicious Base64 strings:"
            ),
            decoder_input,
            encoding_mode,
            mo.md(
                f"#### 🔓 Decoded Command Output:\n```powershell\n{decoded_result}\n```"
            ),
        ]
    )
    step3_view
    return decoded_result, raw_bytes, raw_val, step3_view


@app.cell
def __(df_dns, mo):
    # Step 4: Correlated DNS Telemetry & C2 Analysis
    if not df_dns.empty:
        dns_table = mo.ui.table(
            df_dns,
            selection=None,
            pagination=True,
            page_size=10,
            show_column_summaries=False,
        )
    else:
        dns_table = mo.md("No DNS telemetry recorded.")

    step4_view = mo.vstack(
        [
            mo.md("## 📡 Step 4: Correlated Host DNS Telemetry & C2 Analysis"),
            mo.md(
                "Cross-reference the victim workstation's (`FIN-WS-1002` / `10.0.2.19`) network traffic against the C2 domain identified in the decoded macro payload:"
            ),
            dns_table,
        ]
    )
    step4_view
    return dns_table, step4_view


@app.cell
def __(mo):
    # Step 5: Flag Verification Input Control
    candidate_flag = mo.ui.text(
        placeholder="FLAG{...}",
        label="Enter Extracted DFIR Flag to Verify:",
    )
    return (candidate_flag,)


@app.cell
def __(candidate_flag, hashlib, mo, re):
    val = candidate_flag.value.strip()
    target_hash = "5f458b9db61a55c7839ede55b271e293e24fee62fe40cb384d55445b9b5666ae"

    if not val:
        flag_feedback = mo.md(
            "Enter the flag recovered from the macro payload or correlated DNS telemetry."
        )
        ioc_view = mo.md("🔒 *Threat Intelligence & IOC Report locked until valid incident flag is verified.*")
    elif hashlib.sha256(val.encode()).hexdigest() == target_hash:
        flag_feedback = mo.callout(
            mo.md(
                "🎉 **FLAG VERIFIED CORRECT!**\n\n"
                "Your recovered Phishing DFIR flag is confirmed! Now submit this flag in the **Submit Flag** box in the left CyberLab portal pane to register your 100 points and DFIR competency!"
            ),
            kind="success",
        )
        ioc_view = mo.vstack(
            [
                mo.md("### 📋 Confirmed Threat Intelligence Indicators (IOCs):"),
                mo.md("""
                | IOC Type | Value | Threat Context |
                | :--- | :--- | :--- |
                | **Spoofed Sender Domain** | `quickbooks-invoicing-update.com` | Typosquatting Intuit QuickBooks |
                | **Originating Mail Server IP** | `203.0.113.88` | Untrusted external SMTP relay |
                | **Malicious Word Document** | `Invoice_Sept2026_OVERDUE.docm` | Weaponized VBA macro downloader |
                | **Command and Control Domain** | `c2-exfil-node.darknet-routing.org` | Resolved by victim host `10.0.2.19` |
                | **C2 Server IPv4** | `198.51.100.99` | External listener receiving beacon |
                """),
            ]
        )
    elif re.match(r"^FLAG\{.*\}$", val):
        flag_feedback = mo.callout(
            mo.md(
                "❌ Incorrect flag. Verify the decoded PowerShell payload in Step 3 or the C2 notes in Step 4."
            ),
            kind="danger",
        )
        ioc_view = mo.md("🔒 *Threat Intelligence & IOC Report locked until valid incident flag is verified.*")
    else:
        flag_feedback = mo.callout(
            mo.md(
                "⚠️ Flag format invalid. Flags must begin with `FLAG{` and end with `}`."
            ),
            kind="warn",
        )
        ioc_view = mo.md("🔒 *Threat Intelligence & IOC Report locked until valid incident flag is verified.*")

    step5_view = mo.vstack(
        [
            mo.md("## 🏁 Step 5: Verify Incident Flag & Threat Intel Report"),
            candidate_flag,
            flag_feedback,
            mo.md("---"),
            ioc_view,
        ]
    )
    step5_view
    return flag_feedback, ioc_view, step5_view, target_hash, val


if __name__ == "__main__":
    app.run()
