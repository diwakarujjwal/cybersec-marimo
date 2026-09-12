import marimo

__generated_with = "0.24.1"
app = marimo.App(width="full")


@app.cell
def __():
    import hashlib
    import json
    import re
    import sqlite3
    from pathlib import Path
    import marimo as mo
    import pandas as pd

    return Path, hashlib, json, mo, pd, re, sqlite3


@app.cell
def __(Path, sqlite3):
    # Connect to the authentic corporate database
    possible_db_paths = [
        Path("data/corp_directory.db"),
        Path("../data/corp_directory.db"),
        Path("/workspace/data/corp_directory.db"),
        Path("challenges/04-vulnerable-web-app/data/corp_directory.db"),
    ]
    if "__file__" in globals():
        possible_db_paths.insert(
            0, Path(__file__).resolve().parent.parent / "data" / "corp_directory.db"
        )
    db_file = next((p for p in possible_db_paths if p.exists()), None)
    conn = sqlite3.connect(db_file if db_file else ":memory:", check_same_thread=False)
    return conn, db_file, possible_db_paths


@app.cell
def __(mo):
    # Analyst Sidebar: OWASP Classification, MITRE ATT&CK & Checklist
    check_probe = mo.ui.checkbox(
        label="1. Probe input for SQL syntax errors (single quote)", value=False
    )
    check_bypass = mo.ui.checkbox(
        label="2. Confirm boolean tautology bypass (' OR 1=1 --)", value=False
    )
    check_cols = mo.ui.checkbox(
        label="3. Enumerate query column count (UNION SELECT)", value=False
    )
    check_schema = mo.ui.checkbox(
        label="4. Enumerate schema via sqlite_master injection", value=False
    )
    check_flag = mo.ui.checkbox(
        label="5. Exfiltrate secret audit records & verify flag", value=False
    )

    hints = mo.accordion(
        {
            "💡 Hint 1: Syntax Probing": mo.md(
                "Test input with a single quote (`'`). If the application returns a syntax error, untrusted input is concatenated directly into the query string without sanitization."
            ),
            "💡 Hint 2: Determining Column Count": mo.md(
                "UNION SELECT injections require the injected query to return the exact same number of columns as the original query. Test `' UNION SELECT 1 --`, `' UNION SELECT 1, 2 --`, etc., until no column mismatch error occurs."
            ),
            "💡 Hint 3: Database Schema Enumeration": mo.md(
                "In SQLite, all table schemas are cataloged in `sqlite_master`. Inject a UNION query selecting `name` and `sql` from `sqlite_master` to uncover hidden internal tables."
            ),
        }
    )

    sidebar_content = mo.vstack(
        [
            mo.md("## 🌐 CyberLab AppSec Console"),
            mo.md("**Incident ID**: `INC-0404-SQLI-PORTAL`"),
            mo.md("**Target**: `Corporate Directory API`"),
            mo.md("**Classification**: `OWASP A03:2021` | Severity: **HIGH**"),
            mo.md("---"),
            mo.md("### 🎯 Penetration Testing Checklist"),
            check_probe,
            check_bypass,
            check_cols,
            check_schema,
            check_flag,
            mo.md("---"),
            mo.md("### 🗺️ Vulnerability Mapping"),
            mo.md(
                "- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command\n"
                "- **OWASP Top 10**: A03:2021 - Injection\n"
                "- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)"
            ),
            mo.md("---"),
            hints,
        ]
    )

    mo.sidebar(sidebar_content)
    return (
        check_bypass,
        check_cols,
        check_flag,
        check_probe,
        check_schema,
        hints,
        sidebar_content,
    )


@app.cell
def __(conn, mo):
    # Header Banner & Stat KPIs
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM employees")
    emp_count = cur.fetchone()[0]

    header_view = mo.vstack(
        [
            mo.md("""
            # 🌐 Incident 0404: Corporate Directory Security Assessment
            ### Web Application Security, SQL Injection & Data Exfiltration Workbench
            """),
            mo.callout(
                mo.md(
                    "**AppSec Penetration Testing Notice**: The Corporate Employee Directory search endpoint concatenates untrusted user queries directly into SQL commands. Exploit the SQL injection vulnerability to determine query structure, enumerate backend schema objects via `sqlite_master`, extract restricted audit records, and demonstrate secure parameterized remediation."
                ),
                kind="warn",
            ),
            mo.hstack(
                [
                    mo.stat(
                        value="Vulnerable",
                        label="Input Sanitization",
                        caption="Direct String Interpolation",
                        direction="increase",
                        bordered=True,
                    ),
                    mo.stat(
                        value=f"{emp_count} Records",
                        label="Visible Directory Entries",
                        caption="Public Employees Table",
                        bordered=True,
                    ),
                    mo.stat(
                        value="SQLite 3",
                        label="Database Engine",
                        caption="Backend Relational DBMS",
                        bordered=True,
                    ),
                    mo.stat(
                        value="OWASP A03",
                        label="Risk Classification",
                        caption="Critical SQL Injection Flaw",
                        bordered=True,
                    ),
                ],
                justify="start",
                gap=1,
            ),
        ]
    )
    header_view
    return cur, emp_count, header_view


@app.cell
def __(mo):
    # Step 1: Interactive SQL Injection Controls
    payload_preset = mo.ui.dropdown(
        options=[
            "Custom Injection Query",
            "1. Standard Search: 'Alice'",
            "2. Syntax Error Probe: '''",
            "3. Boolean Filter Bypass: ''' OR 1=1 --'",
            "4. Column Count Enumeration: ''' UNION SELECT 1, 2, 3, 4 --'",
        ],
        value="1. Standard Search: 'Alice'",
        label="Methodology Preset:",
    )

    custom_payload_input = mo.ui.text(
        value="Alice",
        placeholder="Enter search term or SQL injection payload (e.g. ' UNION SELECT ...)...",
        label="SQL Injection Input (Query Parameter `q`):",
        full_width=True,
    )

    return custom_payload_input, payload_preset


@app.cell
def __(conn, custom_payload_input, mo, payload_preset, pd):
    # Step 1: Live Database Query Execution & Results Rendering
    active_query = custom_payload_input.value
    if payload_preset.value == "1. Standard Search: 'Alice'":
        active_query = "Alice"
    elif payload_preset.value == "2. Syntax Error Probe: '''":
        active_query = "'"
    elif payload_preset.value == "3. Boolean Filter Bypass: ''' OR 1=1 --'":
        active_query = "' OR 1=1 --"
    elif (
        payload_preset.value
        == "4. Column Count Enumeration: ''' UNION SELECT 1, 2, 3, 4 --'"
    ):
        active_query = "' UNION SELECT 1, 2, 3, 4 --"

    constructed_sql = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{active_query}%'"

    query_success = False
    query_error = ""
    result_rows = []

    try:
        cur_exec = conn.cursor()
        cur_exec.execute(constructed_sql)
        result_rows = cur_exec.fetchall()
        query_success = True
    except Exception as err:
        query_error = str(err)
        query_success = False

    if query_success:
        df_results = pd.DataFrame(
            result_rows,
            columns=[
                "Col 1 (id)",
                "Col 2 (name)",
                "Col 3 (department)",
                "Col 4 (email)",
            ],
        )
        query_status_badge = mo.callout(
            mo.md(
                f"✅ **Database Execution Succeeded**: `{len(df_results)}` row(s) returned."
            ),
            kind="success",
        )
        results_view = mo.ui.table(
            df_results,
            selection=None,
            pagination=True,
            page_size=8,
            show_column_summaries=False,
        )
    else:
        df_results = pd.DataFrame()
        query_status_badge = mo.callout(
            mo.md(
                f"❌ **Database Execution Error**: `{query_error}`\n\n*This error indicates unsanitized SQL syntax injection!*"
            ),
            kind="danger",
        )
        results_view = mo.md("")

    step1_view = mo.vstack(
        [
            mo.md("## 🔬 Step 1: Interactive SQL Injection Console"),
            mo.md(
                "Test search inputs and SQL injection strings against the target employee directory. Observe the generated backend SQL statement and the returned database records:"
            ),
            payload_preset,
            custom_payload_input,
            mo.md("---"),
            mo.md("#### 🖥️ Backend SQL Query Executed:"),
            mo.md(f"```sql\n{constructed_sql}\n```"),
            query_status_badge,
            results_view,
        ]
    )
    step1_view
    return (
        active_query,
        constructed_sql,
        cur_exec,
        df_results,
        query_error,
        query_status_badge,
        query_success,
        result_rows,
        results_view,
        step1_view,
    )


@app.cell
def __(mo):
    # Step 2: Secure Code Remediation
    remediation_view = mo.vstack(
        [
            mo.md("## 🛡️ Step 2: Secure Code Remediation (Parameterized Queries)"),
            mo.md("""
            SQL injection occurs when untrusted input is interpolated directly into SQL syntax.
            """),
            mo.md("""
            #### ❌ Vulnerable Implementation:
            ```python
            # Untrusted input 'q' is formatted directly into the SQL string:
            sql = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{q}%'"
            cursor.execute(sql)
            ```
            
            #### ✅ Secure Parameterized Implementation:
            ```python
            # The database engine treats the query parameter strictly as literal data:
            sql = "SELECT id, name, department, email FROM employees WHERE name LIKE ?"
            cursor.execute(sql, (f"%{q}%",))
            ```
            """),
            mo.callout(
                mo.md(
                    "**Security Guarantee**: In a parameterized query, SQL metacontrol characters like quotes (`'`) or keywords (`UNION SELECT`) are never interpreted as SQL syntax, neutralizing 100% of injection attacks."
                ),
                kind="success",
            ),
        ]
    )
    remediation_view
    return (remediation_view,)


@app.cell
def __(mo):
    # Step 3: Flag Input Control
    candidate_flag = mo.ui.text(
        placeholder="FLAG{...}",
        label="Enter Extracted Payroll Audit Flag to Verify:",
    )
    return (candidate_flag,)


@app.cell
def __(candidate_flag, hashlib, mo, re):
    val = candidate_flag.value.strip()
    

    if not val:
        flag_feedback = mo.md(
            "Enter the flag exfiltrated from the internal payroll audit records."
        )
        report_view = mo.md("🔒 *Audit Finding Verification Report locked until valid flag is provided.*")
    elif val == "FLAG{sqli_union_payroll_leak_pwned}":
        flag_feedback = mo.callout(
            mo.md(
                "🎉 **FLAG VERIFIED CORRECT!**\n\n"
                "Your exfiltrated payroll audit finding is confirmed! Now copy and submit this flag in the **Submit Flag** box in the left CyberLab portal pane to register your 150 points and Web Application Security competency!"
            ),
            kind="success",
        )
        report_view = mo.vstack(
            [
                mo.md("### 📋 Confirmed Vulnerability Assessment Report:"),
                mo.md("""
                | Vulnerability Factor | Assessment Detail |
                | :--- | :--- |
                | **Vulnerability Class** | In-Band Union-Based SQL Injection (CWE-89) |
                | **Vulnerable Parameter** | `q` (GET request query parameter) |
                | **Original Query Arity** | 4 Columns (`id, name, department, email`) |
                | **Exfiltrated Table** | `payroll_audit` |
                | **Root Cause** | Unsanitized string interpolation in query builder |
                | **Remediation Status** | Parameterized query specification delivered |
                """),
            ]
        )
    elif re.match(r"^FLAG\{.*\}$", val):
        flag_feedback = mo.callout(
            mo.md(
                "❌ Incorrect flag. Use UNION injection to discover hidden tables in `sqlite_master`, then extract records from the internal audit table."
            ),
            kind="danger",
        )
        report_view = mo.md("🔒 *Audit Finding Verification Report locked until valid flag is provided.*")
    else:
        flag_feedback = mo.callout(
            mo.md(
                "⚠️ Flag format invalid. Flags must begin with `FLAG{` and end with `}`."
            ),
            kind="warn",
        )
        report_view = mo.md("🔒 *Audit Finding Verification Report locked until valid flag is provided.*")

    step3_view = mo.vstack(
        [
            mo.md("## 🏁 Step 3: Verify Exfiltrated Incident Flag & Audit Report"),
            candidate_flag,
            flag_feedback,
            mo.md("---"),
            report_view,
        ]
    )
    step3_view
    return flag_feedback, report_view, step3_view, target_hash, val


if __name__ == "__main__":
    app.run()
