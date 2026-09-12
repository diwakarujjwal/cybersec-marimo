"""Intentionally vulnerable web application for educational SQL injection."""
import sys
import argparse
import sqlite3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote


def init_database():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT, email TEXT)")
    cur.execute("CREATE TABLE payroll_audit (id INTEGER PRIMARY KEY, employee_id INT, notes TEXT, flag TEXT)")

    employees = [
        (1, "Alice Smith", "Engineering", "alice@corp.internal"),
        (2, "Bob Miller", "Human Resources", "bob@corp.internal"),
        (3, "Charlie Davis", "Finance", "charlie@corp.internal"),
        (4, "Dana White", "Executive", "dana@corp.internal"),
    ]
    cur.executemany("INSERT INTO employees VALUES (?, ?, ?, ?)", employees)

    audits = [
        (1, 4, "Executive bonus disbursement verification", "FLAG{sqli_union_payroll_leak_pwned}"),
        (2, 3, "Quarterly tax withholding reconciliation", "N/A"),
    ]
    cur.executemany("INSERT INTO payroll_audit VALUES (?, ?, ?, ?)", audits)
    conn.commit()
    return conn


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CorpDirectory Portal</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
        .container { max-width: 800px; margin: 0 auto; background: #1e293b; padding: 2rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
        h1 { color: #38bdf8; margin-top: 0; }
        .search-box { display: flex; gap: 0.5rem; margin-bottom: 2rem; }
        input[type="text"] { flex: 1; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 1rem; }
        button { background: #0284c7; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
        button:hover { background: #0369a1; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; background: #0369a1; color: #e0f2fe; }
        .sql-error { background: #7f1d1d; color: #fecaca; padding: 1rem; border-radius: 6px; margin-top: 1rem; font-family: monospace; }
    </style>
</head>
<body>
<div class="container">
    <h1>🏢 Corporate Directory Portal</h1>
    <p>Search active corporate staff by name or department.</p>
    <form class="search-box" method="GET" action="/">
        <input type="text" name="q" placeholder="Search employee name... (e.g. Alice)" value="{query}">
        <button type="submit">Search</button>
    </form>
    {results_html}
</div>
</body>
</html>
"""


class VulnerableAppHandler(BaseHTTPRequestHandler):
    db_conn = None

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path in ["/", "/index.html"]:
            query = qs.get("q", [""])[0]
            results_html = ""

            if query:
                try:
                    # Intentionally vulnerable SQL concatenation!
                    sql = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{query}%'"
                    cur = self.db_conn.cursor()
                    cur.execute(sql)
                    rows = cur.fetchall()

                    results_html = "<table><thead><tr><th>ID</th><th>Name</th><th>Department</th><th>Email</th></tr></thead><tbody>"
                    for r in rows:
                        results_html += f"<tr><td>{r[0]}</td><td><strong>{r[1]}</strong></td><td><span class='badge'>{r[2]}</span></td><td>{r[3]}</td></tr>"
                    results_html += "</tbody></table>"
                except Exception as e:
                    results_html = f"<div class='sql-error'>Database Query Error: {e}<br>Query: <code>{sql}</code></div>"

            response_body = HTML_TEMPLATE.format(query=query, results_html=results_html)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(response_body.encode("utf-8"))

        elif parsed.path == "/api/search":
            query = qs.get("q", [""])[0]
            try:
                sql = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{query}%'"
                cur = self.db_conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
                data = [{"id": r[0], "name": r[1], "department": r[2], "email": r[3]} for r in rows]
                status, body = 200, json.dumps({"success": True, "data": data})
            except Exception as e:
                status, body = 500, json.dumps({"success": False, "error": str(e), "sql": sql})

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    VulnerableAppHandler.db_conn = init_database()
    server = HTTPServer((args.host, args.port), VulnerableAppHandler)
    print(f"Vulnerable web app serving on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

