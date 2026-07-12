# OWASP API Security Top 10 (2023) Mapping

This is the API-security view of the lab. Several findings from the web-app
mapping ([OWASP_MAPPING.md](OWASP_MAPPING.md)) map directly onto API-specific
risk categories; two endpoints (`/admin/users`, `/profile`) were added to cover
risks that are API-specific.

| API Risk | Finding | Vulnerable | Secure |
|---|---|---|---|
| API1:2023 – Broken Object Level Authorization (BOLA) | IDOR on notes | `GET /vulnerable/notes/{id}` | `GET /secure/notes/{id}` |
| API2:2023 – Broken Authentication | Weak JWT (hardcoded secret, no expiry) | `POST /vulnerable/login` | `POST /secure/login` |
| API3:2023 – Broken Object Property Level Authorization (Mass Assignment) | Blind merge of client fields | `POST /vulnerable/profile` | `POST /secure/profile` |
| API4:2023 – Unrestricted Resource Consumption | Unbounded upload | `POST /vulnerable/upload` | `POST /secure/upload` (1 MB cap) |
| API5:2023 – Broken Function Level Authorization (BFLA) | Admin listing without authz | `GET /vulnerable/admin/users` | `GET /secure/admin/users` |
| API7:2023 – Server Side Request Forgery | Unvalidated URL fetch | `GET /vulnerable/fetch` | `GET /secure/fetch` |
| API8:2023 – Security Misconfiguration | Debug / info disclosure | `GET /vulnerable/debug` | `GET /secure/debug` |

## Notes on the mappings

- **BOLA vs BFLA.** BOLA (API1) is *object*-level: can user A read user B's object?
  The notes IDOR demonstrates this. BFLA (API5) is *function*-level: can a
  non-admin invoke an admin function at all? The `/admin/users` endpoint
  demonstrates this — the vulnerable version has no authorization check, the
  secure version requires an authenticated admin.
- **Mass assignment (API3).** The vulnerable `/profile` blindly applies every
  client-supplied key, letting a caller set `role: admin`. The secure version
  binds only an explicit field whitelist (`display_name`).
- **Unrestricted resource consumption (API4).** The secure upload enforces a
  1 MB size cap (`max_upload_bytes`); the vulnerable one does not, allowing an
  attacker to exhaust memory/disk.
