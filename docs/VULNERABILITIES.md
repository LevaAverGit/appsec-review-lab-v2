# Vulnerabilities Reference

Each vulnerability has a vulnerable endpoint, a secure counterpart, OWASP category, CWE, and test coverage.

---

## 1. SQL Injection

- **Vulnerable:** `GET /vulnerable/search?q=`
- **Secure:** `GET /secure/search?q=`
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-89
- **Root cause:** f-string interpolation: `f"SELECT ... LIKE '%{q}%'"`
- **Fix:** Parameterized query: `conn.execute("... LIKE ?", (f"%{q}%",))`

---

## 2. IDOR

- **Vulnerable:** `GET /vulnerable/notes/{id}?user_id=`
- **Secure:** `GET /secure/notes/{id}` (requires JWT)
- **OWASP:** A01:2021 – Broken Access Control
- **CWE:** CWE-639
- **Root cause:** User identity taken from query parameter, not from authenticated token.
- **Fix:** Extract `user_id` from validated JWT, add `AND user_id = ?` ownership check.

---

## 3. Weak JWT

- **Vulnerable:** `POST /vulnerable/login`, `GET /vulnerable/me`
- **Secure:** `POST /secure/login`, `GET /secure/me`
- **OWASP:** A07:2021 – Identification and Authentication Failures
- **CWE:** CWE-287, CWE-347
- **Root cause:** Hardcoded `"secret"` signing key; `verify_exp: False` in decode options.
- **Fix:** Secret from environment config; `exp` claim always included and enforced.

---

## 4. SSRF

- **Vulnerable:** `GET /vulnerable/fetch?url=`
- **Secure:** `GET /secure/fetch?url=`
- **OWASP:** A10:2021 – Server-Side Request Forgery
- **CWE:** CWE-918
- **Root cause:** `httpx.get(url)` with no validation.
- **Fix:** `_is_safe_url(url)` — blocks RFC1918, loopback, link-local, and non-HTTP(S) schemes.

---

## 5. Stored XSS

- **Vulnerable:** `POST /vulnerable/comments`, `GET /vulnerable/comments/rendered`
- **Secure:** `POST /secure/comments`, `GET /secure/comments/rendered`
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-79
- **Root cause:** `f"<p>{content}</p>"` stores raw HTML without escaping.
- **Fix:** `html.escape(content)` before constructing HTML. CSP header added.

---

## 6. Insecure File Upload

- **Vulnerable:** `POST /vulnerable/upload`
- **Secure:** `POST /secure/upload`
- **OWASP:** A05:2021 – Security Misconfiguration
- **CWE:** CWE-434, CWE-22
- **Root cause:** No extension check; original filename used as stored path (path traversal).
- **Fix:** Extension whitelist; UUID-based stored name; 1 MB size limit.

---

## 7. Security Misconfiguration

- **Vulnerable:** `GET /vulnerable/debug`
- **Secure:** `GET /secure/debug`
- **OWASP:** A05:2021 – Security Misconfiguration
- **CWE:** CWE-200
- **Root cause:** Debug endpoint returns `os.environ`, JWT secret, DB path.
- **Fix:** Endpoint returns HTTP 404 unconditionally.

---

## 8. Cryptographic Failures

- **Vulnerable:** `POST /vulnerable/register`
- **Secure:** `POST /secure/register`
- **OWASP:** A02:2021 – Cryptographic Failures
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort), CWE-327
- **Root cause:** Passwords hashed with unsalted MD5; the digest is echoed back to the client.
- **Fix:** bcrypt with a per-password salt and tunable work factor; the hash is never returned.

---

## 9. Broken Function Level Authorization (BFLA)

- **Vulnerable:** `GET /vulnerable/admin/users`
- **Secure:** `GET /secure/admin/users`
- **OWASP:** A01:2021 – Broken Access Control · API5:2023 – BFLA
- **CWE:** CWE-285 (Improper Authorization)
- **Root cause:** Admin-only listing exposed with no authorization check; any caller can enumerate users.
- **Fix:** Require an authenticated admin (function-level authorization) before returning data.

---

## 10. Mass Assignment

- **Vulnerable:** `POST /vulnerable/profile`
- **Secure:** `POST /secure/profile`
- **OWASP:** A08:2021 – Software/Data Integrity · API3:2023 – BOPLA
- **CWE:** CWE-915 (Improperly Controlled Modification of Object Attributes)
- **Root cause:** Every client-supplied field is merged into the object, letting a caller set `role: admin`.
- **Fix:** Bind only an explicit field whitelist (`display_name`); ignore privileged fields.
