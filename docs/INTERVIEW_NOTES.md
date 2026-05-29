# Interview Notes

Talking points and expected interview questions for candidates demonstrating this lab.

---

## How to present this project

Start with the purpose: "I built this to demonstrate that I understand not just what a vulnerability is, but how to reproduce it in code, how to fix it, and how to test both sides."

Key points to make:

1. Every vulnerability has both a broken and a fixed version — side by side.
2. Tests prove the broken version is actually broken, and the fixed version actually fixes it.
3. No external tools, no black-box scanning — the logic is readable in the source.

---

## Common questions and answers

### "What's the difference between SQLi and parameterized queries?"

Parameterized queries send the SQL structure and the user data separately to the database engine. The engine never interprets user data as SQL syntax. With string interpolation, the user data and the SQL command are concatenated before parsing, so a user can inject SQL syntax.

### "How does SSRF work, and how did you mitigate it?"

SSRF lets an attacker use the server as a proxy to reach services that aren't exposed to the internet — internal APIs, metadata endpoints, or loopback services. The mitigation is to resolve the target hostname to an IP address and reject RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x), loopback (127.x), link-local (169.254.x), and non-HTTP(S) schemes before making the request.

### "Why did you pin bcrypt<4.0.0?"

Passlib 1.7.4 uses an internal attribute `bcrypt.__about__` that was removed in bcrypt 4.0. Without the pin, passlib falls back to an incompatible code path that raises a `ValueError` on any hash operation. This is a known upstream incompatibility — the correct fix at production scale would be to migrate to `argon2-cffi` or wait for a passlib 2.x release.

### "What's the difference between stored and reflected XSS?"

Stored XSS is persisted in a database and rendered to every user who views the affected page — higher impact. Reflected XSS is injected in a URL parameter and reflected back in a single response — requires the victim to follow a crafted link. This lab demonstrates stored XSS via the comments endpoint.

### "How does IDOR differ from a missing authentication check?"

IDOR is specifically about authorization — the user is authenticated, but there's no check that the requested resource belongs to them. Missing authentication is a different problem (no login at all). The fix for IDOR is to add an ownership constraint (`AND user_id = ?`) to every query that returns user-owned data.

### "What would you do differently in production?"

- Replace SQLite with PostgreSQL and use an ORM (SQLAlchemy) for queries.
- Use `argon2-cffi` or `bcrypt` directly instead of passlib.
- Add rate limiting and request signing on auth endpoints.
- Use a real secrets manager (Vault, AWS Secrets Manager) instead of env vars.
- Add structured audit logging for auth events.
- Add a WAF or API gateway in front of the app.

---

## What this lab does not cover

Be upfront about gaps — this demonstrates junior+ awareness:

- CSRF (cross-site request forgery) — requires browser context
- XXE (XML external entity) — no XML processing in the lab
- Deserialization attacks — no pickle or YAML deserialization
- Race conditions / TOCTOU
- Second-order injection
- Security headers beyond CSP (HSTS, X-Frame-Options, etc.)
- OAuth / SAML flows
- Real-time threat detection or alerting

---

## Positioning

This project is appropriate to mention when an interviewer asks about:

- AppSec knowledge or OWASP awareness
- Code review experience
- Test-driven development
- Python backend projects
- Security engineering portfolio

It is not appropriate to claim it as experience with: production security tools, real vulnerability assessment, or security operations.
