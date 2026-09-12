import marimo

__generated_with = "0.24.1"
app = marimo.App()


@app.cell
def __():
    import base64
    import hashlib
    import json
    import math
    from pathlib import Path
    import re
    import marimo as mo
    import pandas as pd

    return Path, base64, hashlib, json, math, mo, pd, re


@app.cell
def __(Path, math, pd):
    # Locate data files across environments
    possible_dirs = [
        Path("data"),
        Path("../data"),
        Path("/workspace/data"),
        Path("challenges/05-threat-hunting-lotl/data"),
    ]
    if "__file__" in globals():
        possible_dirs.insert(0, Path(__file__).resolve().parent.parent / "data")

    data_dir = next((p for p in possible_dirs if p.exists()), Path("data"))

    proc_file = data_dir / "sysmon_processes.csv"
    dns_file = data_dir / "dns_queries.csv"

    df_proc = pd.read_csv(proc_file) if proc_file.exists() else pd.DataFrame()
    df_dns = pd.read_csv(dns_file) if dns_file.exists() else pd.DataFrame()

    def shannon_entropy(s):
        if not s or not isinstance(s, str):
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    if not df_dns.empty and "query_name" in df_dns.columns:
        df_dns["query_len"] = df_dns["query_name"].str.len()
        df_dns["entropy"] = df_dns["query_name"].apply(shannon_entropy)
        max_entropy = df_dns["entropy"].max()
    else:
        max_entropy = 0.0

    # Locate rogue masqueraded processes
    if not df_proc.empty and "image" in df_proc.columns:
        rogue_proc = df_proc[
            df_proc["image"].str.endswith("svchost.exe", na=False)
            & ~df_proc["image"].str.startswith("C:\\Windows\\System32\\", na=False)
        ]
        rogue_count = len(rogue_proc)
    else:
        rogue_proc = pd.DataFrame()
        rogue_count = 0

    return (
        data_dir,
        df_dns,
        df_proc,
        dns_file,
        max_entropy,
        possible_dirs,
        proc_file,
        rogue_count,
        rogue_proc,
        shannon_entropy,
    )


@app.cell
def __(mo):
    # Analyst Sidebar: Threat Hunting Scope, MITRE ATT&CK & Checklist
    check_lotl = mo.ui.checkbox(
        label="1. Formulate hunt hypothesis for LOLBin masquerading", value=False
    )
    check_proc = mo.ui.checkbox(
        label="2. Detect anomalous svchost outside System32", value=False
    )
    check_domain = mo.ui.checkbox(
        label="3. Extract tunneling domain from command line", value=False
    )
    check_entropy = mo.ui.checkbox(
        label="4. Calculate Shannon entropy to isolate tunneling queries", value=False
    )
    check_decode = mo.ui.checkbox(
        label="5. Reassemble and decode exfiltrated flag", value=False
    )

    hints = mo.accordion(
        {
            "💡 Hint 1: Process Masquerading": mo.md(
                "Genuine Windows `svchost.exe` always executes from `C:\\Windows\\System32\\svchost.exe`. Check **Step 1** for any `svchost.exe` launched from user directories like `AppData\\Local\\Temp`."
            ),
            "💡 Hint 2: Identifying the C2 Domain": mo.md(
                "Inspect the command line parameters of the rogue process in **Step 1**. Notice the `-domain <domain>` argument."
            ),
            "💡 Hint 3: Entropy & Base64 Decoding": mo.md(
                "In **Step 2**, increase the Shannon Entropy slider to `4.0` or higher. Look at queries matching the tunneling domain. In **Step 3**, decode the Base64 subdomain payload to uncover the flag."
            ),
        }
    )

    sidebar_content = mo.vstack(
        [
            mo.md("## 🎯 CyberLab Threat Hunter"),
            mo.md("**Operation**: `CLOUDSNOOP`"),
            mo.md("**Target**: `Finance Workstation Fleet`"),
            mo.md("**Classification**: `TLP:AMBER` | Severity: **HIGH**"),
            mo.md("---"),
            mo.md("### 🎯 Hunting Checklist"),
            check_lotl,
            check_proc,
            check_domain,
            check_entropy,
            check_decode,
            mo.md("---"),
            mo.md("### 🗺️ MITRE ATT&CK Matrix"),
            mo.md(
                "- **T1036.005**: Masquerading: Match Legitimate Name\n"
                "- **T1071.004**: DNS Tunneling\n"
                "- **T1048.003**: Exfiltration Over Alternative Protocol"
            ),
            mo.md("---"),
            hints,
        ]
    )

    mo.sidebar(sidebar_content)
    return (
        check_decode,
        check_domain,
        check_entropy,
        check_lotl,
        check_proc,
        hints,
        sidebar_content,
    )


@app.cell
def __(df_dns, df_proc, max_entropy, mo, rogue_count):
    # Header Banner & Stat KPIs
    header_view = mo.vstack(
        [
            mo.md("""
            # 🎯 Incident 0505: Operation CloudSnoop — Advanced Threat Hunt
            ### Enterprise Threat Hunting: Living-off-the-Land & DNS Tunneling Exfiltration
            """),
            mo.callout(
                mo.md(
                    "**Hunting Hypothesis**: *An adversary established persistence on a finance workstation using process masquerading (`svchost.exe`) and bypassed firewall perimeter controls by exfiltrating sensitive payroll records encoded inside high-entropy DNS subdomain queries.* Hunt across endpoint Sysmon telemetry and network DNS queries to unmask the rogue process, isolate the tunneling channel, and recover the exfiltrated flag."
                ),
                kind="warn",
            ),
            mo.hstack(
                [
                    mo.stat(
                        value=f"{len(df_proc)} Processes",
                        label="Endpoint Sysmon Telemetry",
                        caption="Host: FIN-WS-09",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{rogue_count} Detected",
                        label="Masqueraded Binaries",
                        caption="Non-System32 svchost.exe",
                        direction="increase",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(df_dns)} Lookups",
                        label="Audited DNS Lookups",
                        caption="Internal Resolver Logs",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{max_entropy:.2f} Bits",
                        label="Peak Shannon Entropy",
                        caption="Normal Domain Mean: ~2.5 Bits",
                        direction="increase",
                        bordered=True,
                    ),
                ],
                justify="start",
                gap=1,
            ),
        ]
    )
    header_view
    return (header_view,)


@app.cell
def __(mo):
    # Step 1: Process Masquerading Search Control
    proc_filter = mo.ui.text(
        placeholder="Filter process name, image path, or parameters (e.g. svchost, Temp)...",
        value="",
        label="Process Filter:",
    )
    return (proc_filter,)


@app.cell
def __(df_proc, mo, proc_filter, rogue_proc):
    # Step 1: Process Masquerading Results View
    filtered_proc = df_proc
    search_term = proc_filter.value.strip().lower()
    if search_term:
        filtered_proc = df_proc[
            df_proc["image"].str.contains(search_term, case=False, na=False)
            | df_proc["command_line"].str.contains(search_term, case=False, na=False)
        ]

    proc_table = mo.ui.table(
        filtered_proc,
        selection=None,
        pagination=True,
        page_size=8,
        show_column_summaries=False,
    )

    if search_term and any(term in search_term for term in ["svchost", "temp", "tunnel", "appdata"]) and not rogue_proc.empty:
        r = rogue_proc.iloc[0]
        masquerade_callout = mo.callout(
            mo.md(
                f"🚨 **ROGUE PROCESS DETECTED**:\n\n"
                f"- **Process Name**: `{r.get('process_name', 'svchost.exe')}` (PID: `{r.get('pid', 'N/A')}`)\n"
                f"- **Image Path**: `{r.get('image')}`\n"
                f"- **Command Line**: `{r.get('command_line')}`\n"
                f"- **Threat Assessment**: Legitimate `svchost.exe` only executes from `C:\\Windows\\System32\\`. The command line parameters explicitly initialize a DNS tunneling client pointing to nameserver **`ns-tunnel.attacker-dns.org`**!"
            ),
            kind="danger",
        )
    else:
        masquerade_callout = mo.md("")

    step1_view = mo.vstack(
        [
            mo.md("## 🕵️ Step 1: Endpoint Process Masquerading Analysis"),
            mo.md("### 🔍 Auditing Endpoint Sysmon Process Telemetry:"),
            proc_filter,
            masquerade_callout,
            proc_table,
        ]
    )
    step1_view
    return filtered_proc, masquerade_callout, proc_table, search_term, step1_view


@app.cell
def __(mo):
    # Step 2: DNS Tunneling Entropy Analysis Controls
    entropy_slider = mo.ui.slider(
        start=2.0,
        stop=5.2,
        step=0.1,
        value=3.8,
        label="Minimum Shannon Entropy (H):",
    )
    len_slider = mo.ui.slider(
        start=10,
        stop=120,
        step=5,
        value=30,
        label="Minimum Query Length:",
    )
    dns_search = mo.ui.text(
        placeholder="Filter domain (e.g. attacker-dns.org)...",
        label="Domain Filter:",
    )
    return dns_search, entropy_slider, len_slider


@app.cell
def __(df_dns, dns_search, entropy_slider, len_slider, mo):
    # Step 2: Filtered DNS Tunneling Queries Display
    if not df_dns.empty:
        cand = df_dns[
            (df_dns["entropy"] >= entropy_slider.value)
            & (df_dns["query_len"] >= len_slider.value)
        ]
        if dns_search.value.strip():
            cand = cand[
                cand["query_name"].str.contains(
                    dns_search.value.strip(), case=False, na=False
                )
            ]
        cand = cand.sort_values(by="entropy", ascending=False)
        dns_hunt_table = mo.ui.table(
            cand[
                ["timestamp", "query_name", "query_len", "entropy", "resolver_response"]
            ],
            selection=None,
            pagination=True,
            page_size=8,
            show_column_summaries=False,
        )
    else:
        cand = df_dns
        dns_hunt_table = mo.md("No DNS records found.")

    step2_view = mo.vstack(
        [
            mo.md("## 📡 Step 2: DNS Tunneling Shannon Entropy Analysis"),
            mo.md(
                "Adjust the Shannon Entropy threshold and query length sliders to isolate DNS tunneling activity:"
            ),
            mo.hstack([entropy_slider, len_slider], gap=1),
            dns_search,
            dns_hunt_table,
        ]
    )
    step2_view
    return cand, dns_hunt_table, step2_view


@app.cell
def __(mo):
    # Step 3: Subdomain Decoder Input Control
    decoder_input = mo.ui.text(
        value="",
        placeholder="Paste or enter high-entropy Base64 subdomain chunk from Step 2...",
        label="Subdomain Encoded Data Chunk:",
        full_width=True,
    )
    return (decoder_input,)


@app.cell
def __(base64, decoder_input, mo):
    # Step 3: Subdomain Payload Reactive Decoder & Display
    decoded_text = ""
    val = decoder_input.value.strip()
    if val:
        try:
            padded = val + "=" * (-len(val) % 4)
            decoded_text = base64.urlsafe_b64decode(padded).decode(
                "utf-8", errors="replace"
            )
        except Exception as err:
            decoded_text = f"Decode error: {err}"

    step3_view = mo.vstack(
        [
            mo.md("## 🔓 Step 3: Subdomain Payload Reassembly & Decoder Workbench"),
            mo.md(
                "DNS tunneling protocols break exfiltrated files into Base64 URL-safe chunks appended as subdomains. Copy an anomalous subdomain chunk from Step 2 into the decoder below:"
            ),
            decoder_input,
            mo.md(f"#### 🔓 Reassembled Decoded Secret:\n```text\n{decoded_text}\n```"),
        ]
    )
    step3_view
    return decoded_text, padded, step3_view, val


@app.cell
def __(mo):
    # Step 4: Flag Verification Input Control
    candidate_flag = mo.ui.text(
        placeholder="FLAG{...}",
        label="Enter Extracted DNS Tunneling Flag to Verify:",
    )
    return (candidate_flag,)


@app.cell
def __(candidate_flag, hashlib, mo, re):
    val_flag = candidate_flag.value.strip()
    

    if not val_flag:
        flag_feedback = mo.md(
            "Enter the flag recovered from the decoded DNS tunneling subdomain."
        )
        ioc_view = mo.md("🔒 *Threat Hunting Findings & IOC Report locked until valid flag is verified.*")
    elif val_flag == "FLAG{dns_tunneling_data_exfil_uncovered}":
        flag_feedback = mo.callout(
            mo.md(
                "🎉 **FLAG VERIFIED CORRECT!**\n\n"
                "Your recovered threat hunting flag is verified! Now submit this flag in the **Submit Flag** box in the left CyberLab portal pane to register your 200 points and Threat Hunting competency!"
            ),
            kind="success",
        )
        ioc_view = mo.vstack(
            [
                mo.md("### 📋 Confirmed Threat Hunting Findings (IOCs):"),
                mo.md("""
                | Indicator Type | Value | Threat Context |
                | :--- | :--- | :--- |
                | **Masqueraded Binary** | `svchost.exe` | Executing from `C:\\Users\\jsmith\\AppData\\Local\\Temp` |
                | **Tunneling Tool Parameters** | `-tunnel -domain ns-tunnel.attacker-dns.org` | Directs DNS queries to adversary nameserver |
                | **C2 Nameserver Domain** | `ns-tunnel.attacker-dns.org` | Authoritative nameserver receiving exfil chunks |
                | **Channel Shannon Entropy** | `5.02 bits` | High-entropy obfuscated base64 query names |
                """),
            ]
        )
    elif re.match(r"^FLAG\{.*\}$", val_flag):
        flag_feedback = mo.callout(
            mo.md("❌ Incorrect flag. Verify the decoded Base64 payload in Step 3."),
            kind="danger",
        )
        ioc_view = mo.md("🔒 *Threat Hunting Findings & IOC Report locked until valid flag is verified.*")
    else:
        flag_feedback = mo.callout(
            mo.md(
                "⚠️ Flag format invalid. Flags must begin with `FLAG{` and end with `}`."
            ),
            kind="warn",
        )
        ioc_view = mo.md("🔒 *Threat Hunting Findings & IOC Report locked until valid flag is verified.*")

    step4_view = mo.vstack(
        [
            mo.md("## 🏁 Step 4: Verify Incident Flag & Hunt Findings"),
            candidate_flag,
            flag_feedback,
            mo.md("---"),
            ioc_view,
        ]
    )
    step4_view
    return flag_feedback, ioc_view, step4_view, target_hash, val_flag


if __name__ == "__main__":
    app.run()
