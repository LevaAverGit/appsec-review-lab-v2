# Testing Approach

## Structure

151 tests across 8 modules:

| Module | What it tests |
|---|---|
| `test_sql_injection.py` | Tautology, UNION, destructive payloads; secure parameterized query |
| `test_idor.py` | Cross-user access on vulnerable; ownership enforcement on secure |
| `test_jwt.py` | Forged token, expired token; secure expiry enforcement |
| `test_ssrf.py` | Loopback, RFC1918, file://, ftp:// all blocked; `_is_safe_url` unit tests |
| `test_xss.py` | Script tag stored unescaped on vulnerable; escaped on secure; CSP header |
| `test_file_upload.py` | Extension whitelist; path traversal prevention; size limit |
| `test_security_misc.py` | Debug endpoint exposes secrets; secure returns 404 |
| `test_sast_checks.py` | Pattern detection on temp files; finding fields; real route file comparison |
| `test_dast_checks.py` | All 7 DAST check functions; run_all_checks result set |
| `test_report_service.py` | Report structure; finding fields; markdown content; API endpoints |

## Isolation

Each test gets a fresh SQLite database via pytest's built-in `tmp_path` fixture. Tests cannot interfere with each other regardless of execution order.

## No external requests

All tests use `TestClient` from `fastapi.testclient`. The SSRF guard tests check URL validation logic — no HTTP requests leave the test process.

## Vulnerable-vs-secure pattern

Each vulnerability module tests both sides:
1. The **vulnerable** endpoint demonstrates that the attack succeeds (or that flawed behavior is present).
2. The **secure** endpoint demonstrates that the mitigation works.

This structure means each module serves as both a regression test and a proof-of-concept.
