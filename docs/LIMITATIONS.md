# Limitations

## Scope

This is a controlled lab, not a production security tool or a real application.

- All data is synthetic. No real user data is involved.
- All tests run against an in-process application. No external hosts are contacted.
- SSRF tests validate the guard logic, not actual network behaviour.
- File upload tests use in-memory files. No malicious code is executed.

## Detection gaps

- SAST checks (`sast_checks.py`) use regex patterns and will miss obfuscated code.
- SAST patterns may produce false positives in non-route files.
- DAST checks are purpose-built for this lab's endpoints — they are not a general scanner.
- No coverage of second-order injection, CSRF, XXE, deserialization, or timing attacks.

## Deployment model

- Single-user SQLite — not suitable for concurrent access.
- No authentication on the report endpoints.
- No rate limiting, no request signing, no audit log.
- Upload directory (`/tmp/appsec_lab_uploads`) is not cleaned up automatically.

## What this is not

- Not a replacement for real SAST tools (Semgrep, Bandit, CodeQL).
- Not a replacement for real DAST tools (OWASP ZAP, Burp Suite).
- Not a penetration testing tool — all tests target the local lab application only.
- Not a security framework of any kind.
