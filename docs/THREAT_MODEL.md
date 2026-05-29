# Threat Model

This document applies STRIDE categories to the vulnerabilities demonstrated in this lab.

## System context

The lab application is a single-user SQLite-backed FastAPI service. In a real deployment scenario (even a lab), the threat actors and assets below would apply.

## Assets

| Asset | Description |
|---|---|
| Notes database | User notes including potentially sensitive content |
| User credentials | Usernames and bcrypt password hashes |
| JWT signing secret | Used to sign authentication tokens |
| Uploaded files | Files stored on the server filesystem |
| Server environment | Environment variables, config, internal network |

## Threats by STRIDE category

### Spoofing (S)

| Finding | Threat | Root cause |
|---|---|---|
| FIND-003 (Weak JWT) | Attacker forges a valid JWT for any user_id | Hardcoded `"secret"` signing key |
| FIND-003 (Weak JWT) | Attacker replays an expired token | `verify_exp: False` in decode options |

### Tampering (T)

| Finding | Threat | Root cause |
|---|---|---|
| FIND-001 (SQL Injection) | Attacker modifies query logic to return all rows | f-string SQL interpolation |

### Repudiation (R)

Not directly demonstrated. The lab has no audit logging — a known gap documented in LIMITATIONS.md.

### Information Disclosure (I)

| Finding | Threat | Root cause |
|---|---|---|
| FIND-001 (SQL Injection) | Attacker dumps user credentials via UNION | f-string SQL interpolation |
| FIND-002 (IDOR) | Attacker reads another user's notes | user_id from query param, no ownership check |
| FIND-004 (SSRF) | Attacker retrieves internal service content | No URL validation before outbound request |
| FIND-007 (Misconfiguration) | Attacker reads JWT secret and env vars | Debug endpoint not disabled |

### Denial of Service (D)

Not demonstrated. The lab focuses on confidentiality and integrity issues.

### Elevation of Privilege (E)

| Finding | Threat | Root cause |
|---|---|---|
| FIND-003 (Weak JWT) | Attacker impersonates admin via forged token | Weak signing key |
| FIND-006 (File Upload) | Attacker uploads server-side script for RCE | No extension validation |
| FIND-005 (XSS) | Attacker hijacks another user's session | Unescaped HTML in stored comments |

## Trust boundaries

```
Internet / test client
      │
      ▼ (HTTP)
  FastAPI app
      │
      ├──► SQLite (local file)
      │
      ├──► Filesystem (upload_dir)
      │
      └──► (Vulnerable) simulated internal targets (no real outbound)
           (Secure)    URL guard blocks internal addresses
```

The only real trust boundary in this lab is between the test client and the FastAPI app. All other "external" interactions are simulated or blocked.
