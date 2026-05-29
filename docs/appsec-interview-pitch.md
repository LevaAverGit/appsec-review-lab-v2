# AppSec Interview Pitch — AppSec Review Lab

## 30-Second Pitch (Russian)

> Я сделал AppSec Review Lab — FastAPI-приложение, где живут семь пар: уязвимый эндпоинт и исправленный рядом. Покрыты SQL Injection, XSS, SSRF, IDOR, слабый JWT, небезопасная загрузка файлов и security misconfiguration — всё по OWASP Top 10 (2021). К каждой уязвимости есть тест, который доказывает, что сломанная версия ломается, и тест, который доказывает, что исправленная держит. Плюс heuristic SAST scanner — находит опасные паттерны в исходнике, и in-process DAST — проверяет живые эндпоинты атакующими пейлоадами. 159 тестов, CI зелёный.

---

## 30-Second Pitch (English)

> I built AppSec Review Lab to show that I understand vulnerabilities not just conceptually, but in code. It's a FastAPI application with seven intentionally broken endpoints — SQL injection, XSS, SSRF, IDOR, weak JWT, insecure file upload, and security misconfiguration — each paired with a fixed counterpart. Tests prove the broken version fails and the fixed version passes. On top of that, there's a SAST scanner that detects dangerous source-code patterns and a DAST suite that fires attack payloads at live endpoints. 159 tests, GitHub Actions CI.

---

## How to Explain SAST (in this project)

**What it does:** A regex-based scanner (`app/services/sast_checks.py`) scans Python source files for dangerous patterns:
- `f"SELECT * FROM ... {user_input}"` — SQL string interpolation
- `jwt.encode({...}, "secret", ...)` — hardcoded JWT signing key
- `subprocess.run(f"... {cmd} ...")` — shell injection
- `open(f"... {path} ...")` — path traversal

**What it doesn't do:** It is not Semgrep or Bandit. It uses simple regex patterns and will miss obfuscated code or complex data flows. The honest framing: "This is a demonstration of how SAST tooling works — detecting static patterns that indicate security issues — not a production-grade analyzer."

**Interview angle:** "I understand the difference between heuristic rule-based SAST and data-flow-aware static analysis. My scanner demonstrates the principle. In production I would use Semgrep with the `p/python` and `p/owasp-top-ten` rulesets."

---

## How to Explain DAST (in this project)

**What it does:** An in-process DAST suite (`app/services/dast_checks.py`) sends attack payloads to the running FastAPI application and checks responses:
- SQL injection: `' UNION SELECT id,username,password_hash FROM users --`
- JWT forgery: signs a token with the known-weak `"secret"` key
- SSRF: sends `file:///etc/passwd`, `http://127.0.0.1`, `http://10.0.0.1` as fetch URLs
- XSS: stores `<script>alert(1)</script>` and checks if it's echoed unescaped
- Path traversal: uploads `../../etc/passwd.txt`
- Debug endpoint: checks if `GET /vulnerable/debug` returns `jwt_secret` in plaintext

**What it doesn't do:** No real cross-origin attacks, no browser rendering, no actual data exfiltration. All targets are the local in-process test application.

**Interview angle:** "I know what DAST tools like OWASP ZAP and Burp Suite do — they proxy requests through a running app and replay attack payloads. My in-process DAST shows the same principle at a controlled lab scale: send the payload, observe the behavior, assert the result."

---

## What I Would Improve in Production

1. **Replace regex SAST with Semgrep** — use `semgrep --config p/python --config p/owasp-top-ten` for data-flow-aware analysis
2. **Replace in-process DAST with OWASP ZAP** — use ZAP in daemon mode with a CI integration for authenticated scanning
3. **Replace SQLite with PostgreSQL and SQLAlchemy** — ORM-level parameterized queries as the default pattern
4. **Replace passlib with argon2-cffi** — avoid the bcrypt 4.x compatibility issue and use a more modern KDF
5. **Add rate limiting and request signing** on auth endpoints
6. **Add structured audit logging** — all authentication events to a centralized log sink
7. **Use a real secrets manager** (Vault, AWS Secrets Manager) — not environment variables for JWT secrets

---

## Limitations to State Upfront

These are honest gaps — mentioning them shows junior+ awareness:

- SAST patterns are regex-based, not data-flow-aware — will miss complex injection paths
- DAST checks are simplified — no browser, no real cross-origin attacks
- No coverage of CSRF (requires browser context), XXE (no XML), deserialization (no pickle), SSRF via DNS rebinding
- JWT uses HS256 — in production, RS256 with key rotation is preferred
- No TLS in the lab — all traffic is plaintext (localhost only)
- No audit logging in the vulnerable app — realistic logs would be useful for IR exercises
- SQLite is local-only — not representative of production database architecture

---

## Positioning

This project is appropriate to mention when an interviewer asks about:
- OWASP Top 10 knowledge — you can discuss each item with a concrete code example
- Secure coding practices in Python/FastAPI — show parameterized queries, JWT best practices, input validation
- Test-driven security validation — 159 tests prove both failure and fix
- AppSec tooling awareness — you can explain SAST vs DAST, and their production equivalents

It is NOT appropriate to claim as:
- Production security scanner experience
- Real vulnerability assessment or pentest work
- Full SAST/DAST automation (it demonstrates the principle, not the scale)
