# Product Requirements Document

## Problem

Security engineering candidates often struggle to demonstrate practical AppSec knowledge because most portfolio projects are either too theoretical (blog posts, CTF writeups) or too broad (scanner tools that invoke external APIs). Interviewers want to see evidence that a candidate understands:

1. How vulnerabilities actually manifest in real code.
2. What the correct fix looks like side-by-side.
3. Whether the candidate can write tests that prove the fix works.

## Goal

Build a controlled lab that pairs each vulnerability with a remediated version, covered by tests, with a structured findings report. The lab itself is the artifact — not a tool for scanning other systems.

## Scope

### In scope

- 7 common web vulnerability categories: SQL injection, IDOR, weak JWT, SSRF, stored XSS, insecure file upload, security misconfiguration
- Vulnerable endpoint + secure counterpart per category
- Unit tests verifying both the vulnerability and the fix
- Heuristic SAST and DAST checks against the local application
- Markdown and JSON findings report
- 10 documentation files covering architecture, threat model, remediation, and skills

### Out of scope

- Real vulnerability scanning against external targets
- Runtime agent or browser automation
- Authentication flows beyond JWT (OAuth, SAML, session cookies)
- CSRF, XXE, deserialization, timing side-channels
- Multi-user concurrency or high-throughput ingestion

## Success criteria

- ≥100 tests, 0 failures
- CI green on GitHub Actions
- All 7 vulnerabilities have a test that proves the vulnerable endpoint behaves insecurely
- All 7 vulnerabilities have a test that proves the secure endpoint prevents the attack
- No destructive SQL payloads — only read-only injection patterns in tests
- No overclaiming language
- No AI traces

## Constraints

- Python 3.11+
- FastAPI + Pydantic v2
- SQLite (sync) for lab storage
- All tests run in-process — no outbound network requests
- `bcrypt<4.0.0` pinned due to passlib 1.7.4 compatibility
