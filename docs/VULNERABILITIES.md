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
