# API Overview

## Vulnerable endpoints

| Endpoint | Method | Vulnerability |
|---|---|---|
| `/vulnerable/search?q=` | GET | SQL Injection |
| `/vulnerable/notes/{id}?user_id=` | GET | IDOR |
| `/vulnerable/login` | POST | Weak JWT (hardcoded secret, no expiry) |
| `/vulnerable/me` | GET | Weak JWT verification |
| `/vulnerable/fetch?url=` | GET | SSRF |
| `/vulnerable/comments` | POST | Stored XSS |
| `/vulnerable/comments/rendered` | GET | XSS (raw HTML response) |
| `/vulnerable/upload` | POST | Insecure file upload |
| `/vulnerable/debug` | GET | Security misconfiguration |

## Secure endpoints

| Endpoint | Method | Mitigation |
|---|---|---|
| `/secure/search?q=` | GET | Parameterized query |
| `/secure/notes/{id}` | GET | JWT ownership check |
| `/secure/login` | POST | Strong secret + exp claim |
| `/secure/me` | GET | Expiry enforced |
| `/secure/fetch?url=` | GET | SSRF guard (`_is_safe_url`) |
| `/secure/comments` | POST | `html.escape()` + CSP |
| `/secure/comments/rendered` | GET | Pre-escaped HTML |
| `/secure/upload` | POST | Whitelist + UUID name + size limit |
| `/secure/debug` | GET | Returns 404 |

## Report endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/reports/findings.json` | GET | AppSecReport as JSON |
| `/reports/findings.md` | GET | Markdown incident report |
| `/health` | GET | Liveness check |

## Auth

Secure endpoints that require auth expect: `Authorization: Bearer <token>`. Get a token from `POST /secure/login`.

## Example: Demonstrate SQL injection

```bash
# Start the API
make run-api

# Tautology — returns all notes
curl "http://localhost:8001/vulnerable/search?q=' OR '1'='1"

# UNION — dumps credentials
curl "http://localhost:8001/vulnerable/search?q=' UNION SELECT id,username,password_hash FROM users --"

# Same query on secure endpoint — returns empty list
curl "http://localhost:8001/secure/search?q=' OR '1'='1"
```
