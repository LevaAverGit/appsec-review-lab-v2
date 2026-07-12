# OWASP Top 10 (2021) Mapping

| OWASP Category | Finding | Endpoint |
|---|---|---|
| A01:2021 – Broken Access Control | FIND-002 IDOR (API1: BOLA) | `GET /vulnerable/notes/{id}` |
| A01:2021 – Broken Access Control | FIND-009 BFLA (API5) | `GET /vulnerable/admin/users` |
| A02:2021 – Cryptographic Failures | FIND-008 Weak Password Hash | `POST /vulnerable/register` |
| A08:2021 – Software/Data Integrity | FIND-010 Mass Assignment (API3) | `POST /vulnerable/profile` |
| A03:2021 – Injection (SQL) | FIND-001 SQL Injection | `GET /vulnerable/search` |
| A03:2021 – Injection (XSS) | FIND-005 Stored XSS | `POST /vulnerable/comments` |
| A05:2021 – Security Misconfiguration | FIND-006 Insecure Upload | `POST /vulnerable/upload` |
| A05:2021 – Security Misconfiguration | FIND-007 Debug Endpoint | `GET /vulnerable/debug` |
| A07:2021 – Auth Failures | FIND-003 Weak JWT | `POST /vulnerable/login` |
| A10:2021 – SSRF | FIND-004 SSRF | `GET /vulnerable/fetch` |

Categories not covered (out of scope for this lab): A04 (Insecure Design), A06 (Vulnerable Components), A09 (Logging/Monitoring).

For the API-specific view of these findings (BOLA, BFLA, Mass Assignment, SSRF,
resource consumption), see [API_SECURITY.md](API_SECURITY.md).
