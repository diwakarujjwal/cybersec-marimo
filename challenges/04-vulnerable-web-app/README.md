# INCIDENT 0404 — Corporate Directory & SQL Injection

## Incident Briefing

An internal contractor directory portal was hastily deployed at `corp-directory.internal`. A whistleblower warned that sensitive payroll disbursement audits may be accessible due to unsafe database querying.

## Your Mission

You have been tasked with conducting an educational security assessment of the web application.

1. Interact with the application through your browser interface or the automated Marimo API tester.
2. Identify the input handling flaw on the employee directory search.
3. Construct a SQL injection payload to enumerate the database and extract confidential audit records from the `payroll_audit` table.
4. Retrieve the flag and submit it to CTFd.

**Flag Format**: `FLAG{...}`
