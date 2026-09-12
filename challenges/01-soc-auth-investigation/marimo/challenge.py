import marimo

__generated_with = "0.24.1"
app = marimo.App()


@app.cell
def __():
    import hashlib
    import json
    import re
    from pathlib import Path
    import marimo as mo
    import pandas as pd

    return Path, hashlib, json, mo, pd, re


@app.cell
def __(Path, json, mo, pd):
    # Locate dataset across local sandbox, repository root, and container environments
    possible_paths = [
        Path("data/auth_events.json"),
        Path("../data/auth_events.json"),
        Path("/workspace/data/auth_events.json"),
        Path("challenges/01-soc-auth-investigation/data/auth_events.json"),
    ]
    if "__file__" in globals():
        possible_paths.insert(
            0, Path(__file__).resolve().parent.parent / "data" / "auth_events.json"
        )

    data_file = next((p for p in possible_paths if p.exists()), None)

    if data_file:
        with open(data_file) as f:
            raw_data = json.load(f)
        df = pd.DataFrame(raw_data)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    else:
        df = pd.DataFrame()

    total_events = len(df)
    failed_events = (
        len(df[df["status"] == "FAILURE"])
        if not df.empty and "status" in df.columns
        else 0
    )
    success_events = (
        len(df[df["status"] == "SUCCESS"])
        if not df.empty and "status" in df.columns
        else 0
    )
    unique_ips = (
        df["source_ip"].nunique() if not df.empty and "source_ip" in df.columns else 0
    )

    header_view = mo.vstack(
        [
            mo.md("""
            # 🛡️ SOC Incident 0101: Operation NightShift
            ### Off-Hours Authentication Triage & Credential Stuffing Analysis
            """),
            mo.callout(
                mo.md(
                    "**SOC Alert Notice**: At 03:14 UTC, SIEM triggered a high-severity alert for abnormal authentication failures targeting `PAYROLL-SRV01`, followed by privileged logon activity. Your mission as Tier-1 SOC Analyst is to scope the campaign, identify the compromised account, trace attacker post-exploitation commands, and retrieve the containment flag."
                ),
                kind="warn",
            ),
            mo.hstack(
                [
                    mo.stat(
                        value=f"{total_events:,}",
                        label="Total Events Audited",
                        caption="Window: 2026-09-10 01:00 - 04:00 UTC",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{failed_events:,}",
                        label="Authentication Failures",
                        caption="Event ID 4625 (Logon Failure)",
                        direction="increase",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{success_events:,}",
                        label="Successful Logons",
                        caption="Event ID 4624 (Logon Success)",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{unique_ips}",
                        label="Distinct Source IPs",
                        caption="Internal LAN & External WAN",
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
        data_file,
        df,
        failed_events,
        header_view,
        raw_data,
        success_events,
        total_events,
        unique_ips,
    )


@app.cell
def __(mo):
    # Analyst Sidebar: Incident Context, MITRE Mapping & Checklist
    check_ip = mo.ui.checkbox(
        label="1. Identify brute-forcing external IP", value=False
    )
    check_user = mo.ui.checkbox(label="2. Uncover breached username", value=False)
    check_breach = mo.ui.checkbox(
        label="3. Determine interactive breach timestamp", value=False
    )
    check_proc = mo.ui.checkbox(
        label="4. Spot malicious LOLBin process execution", value=False
    )
    check_flag = mo.ui.checkbox(label="5. Extract containment flag", value=False)

    hints = mo.accordion(
        {
            "💡 Hint 1: Locating the Attacker": mo.md(
                "Use the slider in **Step 2 (Anomaly Triage)** to isolate IP addresses generating an abnormal volume of failed logon attempts. Look for anomalous non-internal public IP addresses."
            ),
            "💡 Hint 2: Confirming Compromise": mo.md(
                "In **Step 3 (Attack Timeline)**, select the suspicious IP identified from the anomaly table. Observe when authentication failures cease and a successful interactive logon (`4624`) occurs."
            ),
            "💡 Hint 3: Analyzing Execution": mo.md(
                "In **Step 4 (Process Forensics)**, review commands executed by the compromised account. Living-off-the-Land Binaries (LOLBins) like `certutil.exe` frequently contain staging parameters or flags."
            ),
        }
    )

    sidebar_content = mo.vstack(
        [
            mo.md("## 🛡️ CyberLab SOC Console"),
            mo.md("**Incident ID**: `INC-0101-NIGHTSHIFT`"),
            mo.md("**Target Host**: `PAYROLL-SRV01` (Windows Server 2022)"),
            mo.md("**Classification**: `TLP:AMBER` | Severity: **HIGH**"),
            mo.md("---"),
            mo.md("### 🎯 Investigation Checklist"),
            check_ip,
            check_user,
            check_breach,
            check_proc,
            check_flag,
            mo.md("---"),
            mo.md("### 🗺️ MITRE ATT&CK Matrix"),
            mo.md(
                "- **T1110.001**: Password Guessing (Brute Force)\n- **T1078.002**: Domain Accounts\n- **T1105**: Ingress Tool Transfer (`certutil`)"
            ),
            mo.md("---"),
            hints,
        ]
    )

    mo.sidebar(sidebar_content)
    return (
        check_breach,
        check_flag,
        check_ip,
        check_proc,
        check_user,
        hints,
        sidebar_content,
    )


@app.cell
def __(mo):
    # Step 1: Raw Telemetry Explorer Controls
    status_filter = mo.ui.dropdown(
        options=["ALL", "FAILURE", "SUCCESS"],
        value="ALL",
        label="Logon Status:",
    )
    user_search = mo.ui.text(
        placeholder="Filter username (e.g., admin)...",
        label="Target User:",
    )
    ip_search = mo.ui.text(
        placeholder="Filter IP (e.g., 198.51.100.42)...",
        label="Source IP:",
    )
    return ip_search, status_filter, user_search


@app.cell
def __(df, ip_search, mo, status_filter, user_search):
    # Filter raw dataframe reactively based on UI inputs
    filtered = df.copy() if not df.empty else df
    if not filtered.empty:
        if status_filter.value != "ALL":
            filtered = filtered[filtered["status"] == status_filter.value]
        if user_search.value.strip():
            filtered = filtered[
                filtered["target_user"].str.contains(
                    user_search.value.strip(), case=False, na=False
                )
            ]
        if ip_search.value.strip():
            filtered = filtered[
                filtered["source_ip"].str.contains(
                    ip_search.value.strip(), case=False, na=False
                )
            ]

    raw_table = mo.ui.table(
        (
            filtered[
                [
                    "timestamp",
                    "event_id",
                    "source_ip",
                    "target_user",
                    "workstation",
                    "status",
                    "auth_package",
                    "process_name",
                ]
            ]
            if not filtered.empty and "event_id" in filtered.columns
            else filtered
        ),
        selection=None,
        pagination=True,
        page_size=15,
        show_column_summaries=False,
    )

    step1_view = mo.vstack(
        [
            mo.md("## 🔍 Step 1: Raw Security Event Log Telemetry"),
            mo.md(
                "Explore the authentication stream across the 1,073 ingested events. Use the filter controls to search by status, username, or source IP:"
            ),
            mo.hstack([status_filter, user_search, ip_search], gap=1),
            raw_table,
        ]
    )
    step1_view
    return filtered, raw_table, step1_view


@app.cell
def __(mo):
    # Step 2: Anomaly Threshold Slider Control
    min_fail_slider = mo.ui.slider(
        start=1,
        stop=220,
        step=5,
        value=20,
        label="Min Failed Logons Threshold for Anomaly Detection:",
    )
    return (min_fail_slider,)


@app.cell
def __(df, min_fail_slider, mo):
    # Step 2: Anomaly Pivot Table Calculation
    if not df.empty and "status" in df.columns:
        failures = df[df["status"] == "FAILURE"]
        fail_summary = (
            failures.groupby("source_ip")
            .agg(
                failed_attempts=("event_id", "count"),
                targeted_users=("target_user", lambda x: list(set(x))[:6]),
                first_attempt=("timestamp", "min"),
                last_attempt=("timestamp", "max"),
            )
            .reset_index()
            .sort_values(by="failed_attempts", ascending=False)
        )
        fail_summary = fail_summary[
            fail_summary["failed_attempts"] >= min_fail_slider.value
        ]
        anomaly_table = mo.ui.table(
            fail_summary,
            selection=None,
            pagination=True,
            page_size=8,
            show_column_summaries=False,
        )
    else:
        fail_summary = df
        anomaly_table = mo.md("No failure records found.")

    step2_view = mo.vstack(
        [
            mo.md("## 🚨 Step 2: High-Frequency Failure Anomaly Triage"),
            mo.md(
                "Brute-force and password spraying attacks generate abnormal volumes of failed logon events (`Event ID 4625`) from external IPs. Adjust the threshold slider to isolate the anomalous source IP:"
            ),
            min_fail_slider,
            anomaly_table,
        ]
    )
    step2_view
    return anomaly_table, fail_summary, failures, step2_view


@app.cell
def __(fail_summary, mo):
    # Step 3: Interactive Source IP Selector for Chronological Timeline
    ip_choices = (
        list(fail_summary["source_ip"].unique())
        if not fail_summary.empty and "source_ip" in fail_summary.columns
        else []
    )
    timeline_ip_select = mo.ui.dropdown(
        options=ip_choices,
        value=ip_choices[0] if ip_choices else None,
        label="Select Source IP to Trace Timeline:",
    )
    return ip_choices, timeline_ip_select


@app.cell
def __(df, mo, timeline_ip_select):
    # Step 3: Chronological Attack Timeline for Selected IP
    selected_ip = timeline_ip_select.value
    if selected_ip and not df.empty:
        ip_events = df[df["source_ip"] == selected_ip].sort_values("timestamp")
        successful_logins = ip_events[ip_events["status"] == "SUCCESS"]

        if not successful_logins.empty:
            first_succ = successful_logins.iloc[0]
            breach_alert = mo.callout(
                mo.md(
                    f"🚨 **BREACH DETECTED**: Source IP `{selected_ip}` obtained **{len(successful_logins)} successful logon(s)** after repeated failures!\n\n"
                    f"- **Compromised Account**: `{first_succ['target_user']}`\n"
                    f"- **Breach Timestamp**: `{first_succ['timestamp']}`\n"
                    f"- **Logon Event ID**: `{first_succ['event_id']}` (Logon Success)"
                ),
                kind="danger",
            )
        else:
            breach_alert = mo.callout(
                mo.md(f"No successful logons detected for `{selected_ip}` in this timeframe."),
                kind="info",
            )

        timeline_table = mo.ui.table(
            ip_events[
                [
                    "timestamp",
                    "event_id",
                    "target_user",
                    "status",
                    "process_name",
                    "command_line",
                ]
            ],
            selection=None,
            pagination=True,
            page_size=10,
            show_column_summaries=False,
        )
    else:
        breach_alert = mo.md("")
        timeline_table = mo.md("Select an IP address above to display its chronological activity.")

    step3_view = mo.vstack(
        [
            mo.md("## ⚡ Step 3: Chronological Attack Timeline Analysis"),
            mo.md(
                "Select a suspicious IP address to trace its activity chronologically. Observe the transition from automated password guessing into an interactive session:"
            ),
            timeline_ip_select,
            breach_alert,
            timeline_table,
        ]
    )
    step3_view
    return (
        breach_alert,
        ip_events,
        selected_ip,
        step3_view,
        successful_logins,
        timeline_table,
    )


@app.cell
def __(df, mo):
    # Step 4: Process Execution & Post-Exploitation Forensics
    if not df.empty and "command_line" in df.columns:
        cmd_events = df[
            df["command_line"].notna() & (df["command_line"] != "")
        ].sort_values("timestamp")

        cmd_cards = []
        for _, row in cmd_events.iterrows():
            is_suspicious = (
                "certutil" in str(row["command_line"]).lower()
                or "whoami" in str(row["command_line"]).lower()
            )
            badge = "🚨 ATTACKER LOLBIN" if is_suspicious else "ℹ️ NORMAL"
            cmd_cards.append(
                f"### {badge}: `{row['process_name']}`\n"
                f"- **Timestamp**: `{row['timestamp']}`\n"
                f"- **Account Context**: `{row['target_user']}`\n"
                f"- **Workstation**: `{row['workstation']}`\n"
                f"- **Executed Command Line**:\n"
                f"```bat\n{row['command_line']}\n```"
            )
        cmd_display = (
            mo.md("\n\n---\n\n".join(cmd_cards))
            if cmd_cards
            else mo.md("No command line telemetry recorded.")
        )
    else:
        cmd_events = df
        cmd_display = mo.md("No command line events recorded.")

    step4_view = mo.vstack(
        [
            mo.md("## 🕵️ Step 4: Living-off-the-Land (LOLBin) Tool Retrieval"),
            mo.md(
                "Adversaries frequently use built-in Windows utilities like `certutil.exe` to bypass perimeter firewalls and download second-stage malware directly onto compromised hosts (`MITRE T1105`). Inspect the commands executed by the compromised user below:"
            ),
            cmd_display,
        ]
    )
    step4_view
    return cmd_cards, cmd_display, cmd_events, step4_view


@app.cell
def __(mo):
    # Step 5: Flag Input Control
    candidate_flag = mo.ui.text(
        placeholder="FLAG{...}",
        label="Enter Extracted Flag to Verify:",
    )
    return (candidate_flag,)


@app.cell
def __(candidate_flag, hashlib, mo, re):
    val = candidate_flag.value.strip()
    

    if not val:
        flag_feedback = mo.md(
            "Enter the flag discovered in the attacker's executed commands above."
        )
        ioc_view = mo.md("🔒 *Threat Intelligence & IOC Report locked until valid incident flag is verified.*")
    elif val == "FLAG{brute_force_pivot_admin_2026}":
        flag_feedback = mo.callout(
            mo.md(
                "🎉 **FLAG VERIFIED CORRECT!**\n\n"
                "Your recovered containment flag is verified! Now submit this flag in the **Submit Flag** box in the left CyberLab portal pane to register your 100 points and SOC competency!"
            ),
            kind="success",
        )
        ioc_view = mo.vstack(
            [
                mo.md("### 📋 Confirmed Threat Intelligence Indicators of Compromise (IOCs):"),
                mo.md("""
                | Indicator Type | Value | Threat Context |
                | :--- | :--- | :--- |
                | **Attacker IPv4** | `198.51.100.42` | Brute-force password spray origin |
                | **Compromised Account** | `admin_finance` | Domain administrative credential breached |
                | **LOLBin Tool Retrieval** | `certutil.exe -urlcache -split -f` | Staged ingress download of `pivot.exe` |
                | **Breach Timestamp** | `2026-09-10 03:14:22 UTC` | Interactive NTLM logon verified |
                """),
            ]
        )
    elif re.match(r"^FLAG\{.*\}$", val):
        flag_feedback = mo.callout(
            mo.md(
                "❌ Incorrect flag. Inspect the arguments passed to `certutil.exe` in Step 4 (Process Forensics)."
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
            mo.md("## 🏁 Step 5: Verify Incident Flag & IOC Report"),
            mo.callout(
                mo.md(
                    "Once you have identified the attacker's staging command line in Step 4, extract the embedded flag and verify it below:"
                ),
                kind="info",
            ),
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
