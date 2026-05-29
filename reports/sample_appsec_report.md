# AppSec Review Lab — Findings Report

Report ID: RPT-2026-001
Generated: 2026-05-26 06:26 UTC
Project: appsec-review-lab

---

## Executive Summary

7 findings documented across 7 vulnerability categories. Each finding has a vulnerable endpoint, a secure counterpart, evidence, and remediation. All tests run against an in-process lab application.

## Severity Breakdown

- **CRITICAL**: 1
- **HIGH**: 6
- **MEDIUM**: 0
- **LOW**: 0

---

## Findings

### FIND-001 — SQL Injection in Search Endpoint

- **Severity:** HIGH
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-89
- **Endpoint:** `GET /vulnerable/search?q=`
- **Confidence:** direct

**Vulnerable behavior:** User input interpolated into SQL query via f-string. Attacker can modify query logic, dump tables, or bypass filters.

**Secure behavior:** Parameterized query with ? placeholder. Input is never interpreted as SQL.

**Evidence:**
- Query: f"SELECT ... WHERE title LIKE '%{q}%'"
- Payload ' OR '1'='1 returns all rows
- Payload ' UNION SELECT id,username,password_hash FROM users -- dumps credentials

**Impact:** Full database read access; potential data exfiltration of all notes and user credentials.

**Remediation:** Use parameterized queries: conn.execute('... WHERE title LIKE ?', (f'%{q}%',))

_Test coverage: `test_sql_injection.py::TestSQLInjection`_

---

### FIND-002 — Insecure Direct Object Reference (IDOR) on Note Access

- **Severity:** HIGH
- **OWASP:** A01:2021 – Broken Access Control
- **CWE:** CWE-639
- **Endpoint:** `GET /vulnerable/notes/{note_id}?user_id=`
- **Confidence:** direct

**Vulnerable behavior:** user_id taken from query parameter, not from authenticated token. Any caller can read any note by supplying any user_id.

**Secure behavior:** user_id extracted from validated JWT. Query enforces AND user_id = ? ownership check.

**Evidence:**
- GET /vulnerable/notes/3?user_id=1 returns bob's note as alice
- No token required on vulnerable endpoint

**Impact:** Any authenticated or unauthenticated user can read all notes in the database.

**Remediation:** Extract user identity from JWT payload, never from request parameters. Enforce ownership with AND user_id = ? in query.

_Test coverage: `test_idor.py::TestIDOR`_

---

### FIND-003 — Weak JWT — Hardcoded Secret and No Expiry Enforcement

- **Severity:** CRITICAL
- **OWASP:** A07:2021 – Identification and Authentication Failures
- **CWE:** CWE-287
- **Endpoint:** `POST /vulnerable/login, GET /vulnerable/me`
- **Confidence:** direct

**Vulnerable behavior:** Token signed with hardcoded string 'secret'. Expiry verification disabled. Attacker can forge tokens or replay stale tokens.

**Secure behavior:** Token signed with long random secret from config. Short expiry (30 min) enforced on every request.

**Evidence:**
- jwt.encode({...}, 'secret', algorithm='HS256') used in login
- options={'verify_exp': False} in decode — expiry never checked
- Forged token with any payload accepted by /vulnerable/me

**Impact:** Authentication bypass. Attacker can impersonate any user by forging a token.

**Remediation:** Generate secret with secrets.token_hex(32). Always include exp claim and let jose enforce it by default.

_Test coverage: `test_jwt.py::TestJWT`_

---

### FIND-004 — Server-Side Request Forgery (SSRF) in Fetch Endpoint

- **Severity:** HIGH
- **OWASP:** A10:2021 – Server-Side Request Forgery
- **CWE:** CWE-918
- **Endpoint:** `GET /vulnerable/fetch?url=`
- **Confidence:** direct

**Vulnerable behavior:** httpx.get(url) called without any host or scheme validation. Attacker can reach internal services, metadata endpoints, or loopback interfaces.

**Secure behavior:** URL validated before request: scheme must be http/https, resolved IP must not be private, loopback, or link-local.

**Evidence:**
- httpx.get(url, timeout=5) with no guards
- GET /vulnerable/fetch?url=http://127.0.0.1/admin reaches localhost
- GET /vulnerable/fetch?url=file:///etc/passwd would read local files

**Impact:** Internal network scanning, cloud metadata access (AWS IMDSv1), or reading local files via file:// scheme.

**Remediation:** Resolve hostname to IP, check against RFC1918/loopback/link-local ranges. Allowlist expected external hostnames when possible.

_Test coverage: `test_ssrf.py::TestSSRF`_

---

### FIND-005 — Stored Cross-Site Scripting (XSS) in Comments

- **Severity:** HIGH
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-79
- **Endpoint:** `POST /vulnerable/comments, GET /vulnerable/comments/rendered`
- **Confidence:** direct

**Vulnerable behavior:** User input stored as raw HTML: f'<p>{content}</p>'. Script tags and event handlers rendered in the browser.

**Secure behavior:** html.escape(content) applied before constructing HTML. CSP header added to rendered response.

**Evidence:**
- Payload <script>alert('xss')</script> stored unescaped
- GET /vulnerable/comments/rendered returns <script>alert('xss')</script> in body

**Impact:** Session hijacking, credential theft, malicious redirects for all users who view the comments page.

**Remediation:** Always escape user content with html.escape() before inserting into HTML. Add Content-Security-Policy header. Consider a templating engine with auto-escaping.

_Test coverage: `test_xss.py::TestXSS`_

---

### FIND-006 — Insecure File Upload — Missing Extension Check and Path Traversal

- **Severity:** HIGH
- **OWASP:** A05:2021 – Security Misconfiguration
- **CWE:** CWE-434
- **Endpoint:** `POST /vulnerable/upload`
- **Confidence:** direct

**Vulnerable behavior:** No file extension validation. Original filename used for stored path. Attacker can upload .php files or use path traversal (../../etc/passwd).

**Secure behavior:** Extension whitelist enforced. Stored filename is a UUID. Size limit checked. No original filename used in filesystem path.

**Evidence:**
- shell.php accepted and stored at upload_dir/shell.php
- ../../etc/passwd used as stored path on vulnerable endpoint

**Impact:** Remote code execution if web server executes uploaded scripts. Overwrite of arbitrary files via path traversal.

**Remediation:** Enforce extension whitelist. Generate UUID-based stored name. Check file size. Consider validating magic bytes, not just extension.

_Test coverage: `test_file_upload.py::TestFileUpload`_

---

### FIND-007 — Security Misconfiguration — Debug Endpoint Exposes Secrets

- **Severity:** HIGH
- **OWASP:** A05:2021 – Security Misconfiguration
- **CWE:** CWE-200
- **Endpoint:** `GET /vulnerable/debug`
- **Confidence:** direct

**Vulnerable behavior:** Debug endpoint returns all environment variables, JWT secret, DB path, and Python executable path in JSON response.

**Secure behavior:** Debug endpoint returns HTTP 404.

**Evidence:**
- GET /vulnerable/debug returns jwt_secret in plaintext
- Environment variables including PATH and PYTHONPATH exposed

**Impact:** Full secret disclosure. Attacker gains JWT signing key, enabling auth bypass. Internal config reveals attack surface.

**Remediation:** Remove debug endpoints before any deployment. Never expose env vars or secrets via API. Use structured logging to safe sinks.

_Test coverage: `test_security_misc.py::TestSecurityMisc`_

---

## Limitations

- All vulnerabilities are demonstrated against synthetic in-process data only.
- SSRF checks test URL validation logic — no actual outbound requests to external hosts.
- File upload tests use in-memory uploads; no real malicious code is executed.
- Detection patterns in sast_checks.py are heuristic and may produce false positives.
- This is a controlled lab, not a comprehensive scanner or a production security tool.

