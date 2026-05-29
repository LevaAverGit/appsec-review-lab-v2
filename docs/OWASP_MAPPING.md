# OWASP Top 10 (2021) Mapping

| OWASP Category | Finding | Endpoint |
|---|---|---|
| A01:2021 – Broken Access Control | FIND-002 IDOR | `GET /vulnerable/notes/{id}` |
| A03:2021 – Injection (SQL) | FIND-001 SQL Injection | `GET /vulnerable/search` |
| A03:2021 – Injection (XSS) | FIND-005 Stored XSS | `POST /vulnerable/comments` |
| A05:2021 – Security Misconfiguration | FIND-006 Insecure Upload | `POST /vulnerable/upload` |
| A05:2021 – Security Misconfiguration | FIND-007 Debug Endpoint | `GET /vulnerable/debug` |
| A07:2021 – Auth Failures | FIND-003 Weak JWT | `POST /vulnerable/login` |
| A10:2021 – SSRF | FIND-004 SSRF | `GET /vulnerable/fetch` |

Categories not covered (out of scope for this lab): A02 (Cryptographic Failures), A04 (Insecure Design), A06 (Vulnerable Components), A08 (Software/Data Integrity), A09 (Logging/Monitoring).
