# AppSec Review Lab

[![CI](https://github.com/LevaAverGit/appsec-review-lab-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/LevaAverGit/appsec-review-lab-v2/actions/workflows/ci.yml)

A controlled lab demonstrating 8 common web vulnerabilities with secure counterparts, SAST/DAST checks, and structured reporting — mapped to both the [OWASP Top 10](docs/OWASP_MAPPING.md) and the [OWASP API Security Top 10](docs/API_SECURITY.md) (BOLA, BFLA, Mass Assignment, SSRF).

Built to demonstrate AppSec awareness, secure coding, and Python backend skills at a junior/junior+ level. Not a production security tool.

**Quick look:** `python scripts/demo.py` runs every vulnerable/secure pair side by side — see the captured output in [docs/DEMO.md](docs/DEMO.md).

---

## What This Project Demonstrates

- **7 vulnerability pairs** — each vulnerability has an intentionally flawed endpoint and a secure counterpart with an explicit fix
- **OWASP Top 10 (2021)** — 7 of 10 categories covered: A01, A03 (twice), A05 (twice), A07, A10
- **SAST checks** — regex pattern scanner that finds dangerous coding patterns in Python source
- **DAST checks** — in-process payload tests that probe running endpoints with attack payloads
- **Structured reporting** — Markdown and JSON AppSec reports with findings model (Finding, AppSecReport)
- **FastAPI backend** — Pydantic v2 models, JWT auth, multipart file upload, parameterized queries
- **180 tests, 0 failures** — TestClient, tmp_path DB isolation, no mocks
- **15 docs** — PRD, threat model, secure code review, remediation guide, interview notes, and more

---

## Vulnerabilities Covered

| # | Vulnerability | OWASP | CWE | Vulnerable | Secure |
|---|---|---|---|---|---|
| 1 | SQL Injection | A03:2021 | CWE-89 | `GET /vulnerable/search` | `GET /secure/search` |
| 2 | IDOR | A01:2021 | CWE-639 | `GET /vulnerable/notes/{id}` | `GET /secure/notes/{id}` |
| 3 | Weak JWT | A07:2021 | CWE-287/347 | `POST /vulnerable/login` | `POST /secure/login` |
| 4 | SSRF | A10:2021 | CWE-918 | `GET /vulnerable/fetch` | `GET /secure/fetch` |
| 5 | Stored XSS | A03:2021 | CWE-79 | `POST /vulnerable/comments` | `POST /secure/comments` |
| 6 | Insecure Upload | A05:2021 | CWE-434/22 | `POST /vulnerable/upload` | `POST /secure/upload` |
| 7 | Security Misconfig | A05:2021 | CWE-200 | `GET /vulnerable/debug` | `GET /secure/debug` |

---

## SAST Pattern Coverage

The heuristic scanner (`app/services/sast_checks.py`) flags the following dangerous
Python coding patterns, each mapped to a CWE:

| Pattern | CWE | Severity |
|---|---|---|
| `SQL_INJECTION_FSTRING` / `SQL_INJECTION_FORMAT` | CWE-89 | high |
| `HARDCODED_SECRET` | CWE-798 | high |
| `WEAK_PASSWORD_HASH` (MD5/SHA1) | CWE-916 | high |
| `SSRF_UNCHECKED_REQUEST` | CWE-918 | medium |
| `XSS_RAW_HTML` | CWE-79 | high |
| `PATH_TRAVERSAL` | CWE-22 | high |
| `JWT_WEAK_OPTIONS` (verify_exp disabled) | CWE-347 | critical |
| `DEBUG_ENDPOINT_ENV_DUMP` | CWE-200 | medium |
| `INSECURE_DESERIALIZATION` (pickle/marshal/yaml.load) | CWE-502 | high |
| `OS_COMMAND_INJECTION` (os.system/os.popen/shell=True) | CWE-78 | critical |
| `DISABLED_TLS_VERIFICATION` (verify=False) | CWE-295 | high |

Command injection and disabled TLS verification are walked through in
[docs/COMMAND_INJECTION_REVIEW.md](docs/COMMAND_INJECTION_REVIEW.md).

---

## Quickstart

```bash
# Python 3.11+ required
python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

# Or with make
make install

# Run all tests
make test

# Start API
make run-api
# http://127.0.0.1:8001/docs
```

---

## Demo: SQL Injection

```bash
# Tautology — returns all rows
curl "http://localhost:8001/vulnerable/search?q=' OR '1'='1"

# UNION injection — dumps user credentials
curl "http://localhost:8001/vulnerable/search?q=' UNION SELECT id,username,password_hash FROM users --"

# Same payload on secure endpoint — returns empty list (parameterized query)
curl "http://localhost:8001/secure/search?q=' OR '1'='1"
```

---

## Architecture

```
app/
├── api/
│   ├── routes_vulnerable.py  ← 7 intentionally flawed endpoints
│   ├── routes_secure.py      ← 7 mitigated counterparts
│   └── routes_reports.py     ← /reports/findings.json and .md
├── services/
│   ├── sast_checks.py        ← regex pattern scanner
│   ├── dast_checks.py        ← in-process payload checks
│   └── report_service.py     ← Finding + AppSecReport generation
├── db/                       ← SQLite schema + seed data
└── models/schemas.py         ← Finding, AppSecReport, User, Note
```

See `docs/ARCHITECTURE.md` for full details.

---

## Reports

```bash
# JSON report
curl http://localhost:8001/reports/findings.json

# Markdown report
curl http://localhost:8001/reports/findings.md
```

Sample reports: `reports/sample_findings.json`, `reports/sample_appsec_report.md`

---

## Tests

```bash
make test  # 180 tests
```

| Module | Coverage |
|---|---|
| `test_sql_injection.py` | Tautology, UNION, destructive payloads; parameterized query safe |
| `test_idor.py` | Cross-user access on vulnerable; ownership enforcement on secure |
| `test_jwt.py` | Forged token, expired token accepted/rejected; exp claim enforced |
| `test_ssrf.py` | Loopback, RFC1918, file://, ftp:// blocked; `_is_safe_url` unit tests |
| `test_xss.py` | Script tag stored raw vs escaped; CSP header present |
| `test_file_upload.py` | Extension whitelist; path traversal prevention; size limit |
| `test_security_misc.py` | Debug exposes secrets vs returns 404 |
| `test_sast_checks.py` | Pattern detection; finding fields; real route file comparison |
| `test_dast_checks.py` | All 7 check functions; run_all_checks result set |
| `test_report_service.py` | Finding fields; markdown sections; API endpoints |

---

## Project Structure

```
appsec-review-lab/
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── routes_vulnerable.py
│   │   ├── routes_secure.py
│   │   └── routes_reports.py
│   ├── core/config.py
│   ├── db/
│   │   ├── database.py
│   │   └── schema.sql
│   ├── models/schemas.py
│   └── services/
│       ├── sast_checks.py
│       ├── dast_checks.py
│       └── report_service.py
├── tests/                     180 tests
├── docs/                      16 documentation files
├── reports/
│   ├── sample_appsec_report.md
│   └── sample_findings.json
├── .github/workflows/ci.yml
├── Makefile
├── pyproject.toml
└── requirements.txt
```

---

## Documentation

| File | Contents |
|---|---|
| `docs/PRD.md` | Project requirements — scope, goals, constraints |
| `docs/THREAT_MODEL.md` | STRIDE threat model for the lab application |
| `docs/ARCHITECTURE.md` | System structure, request flow, storage model |
| `docs/VULNERABILITIES.md` | Per-vulnerability reference: root cause, fix, CWE |
| `docs/OWASP_MAPPING.md` | OWASP Top 10 (2021) category mapping |
| `docs/FINDINGS_MODEL.md` | Finding and AppSecReport data models |
| `docs/SECURE_CODE_REVIEW.md` | Code review checklist for each vulnerability type |
| `docs/REMEDIATION_GUIDE.md` | Step-by-step remediation with code examples |
| `docs/REPORT_FORMAT.md` | JSON and Markdown report structure |
| `docs/API_OVERVIEW.md` | Endpoint reference table with examples |
| `docs/TESTING_APPROACH.md` | Test structure, isolation, what each module covers |
| `docs/SETUP.md` | Install and run instructions |
| `docs/SKILLS_MAPPING.md` | Competency table for each demonstrated skill |
| `docs/LIMITATIONS.md` | Scope limits and what the project does not cover |
| `docs/INTERVIEW_NOTES.md` | Talking points, expected questions, positioning |
| `docs/appsec-interview-pitch.md` | RU/EN pitch, SAST/DAST explanation, Q&A, production notes |

---

## What This Is Not

- Not a production application
- Not a real vulnerability scanner (SAST/DAST checks are heuristic demonstrations)
- Not a replacement for Semgrep, Bandit, OWASP ZAP, or Burp Suite
- All exploit-style tests target the local in-process lab application only — no external hosts are contacted

---

## Limitations

See `docs/LIMITATIONS.md`. Key points:

- All data is synthetic — no real systems involved
- SAST patterns are regex-based and will miss obfuscated code
- No coverage of CSRF, XXE, deserialization, timing attacks
- Upload directory is not cleaned up automatically

---

## Skills Demonstrated

See `docs/SKILLS_MAPPING.md` for a full competency mapping.

Demonstrates junior/junior+ readiness for AppSec engineering and secure Python backend tasks:

- Python 3.11, FastAPI, Pydantic v2, SQLite, pytest
- OWASP Top 10 (2021) practical knowledge
- Vulnerable vs secure code pairs with explicit mitigations
- JWT implementation (weak and secure)
- SSRF guard implementation
- Heuristic SAST and DAST tooling
- Structured AppSec reporting

---

## License

MIT
