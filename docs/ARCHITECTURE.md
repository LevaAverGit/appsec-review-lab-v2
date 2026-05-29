# Architecture

## Overview

```
appsec-review-lab/
├── app/
│   ├── api/
│   │   ├── routes_vulnerable.py   7 intentionally vulnerable endpoints
│   │   ├── routes_secure.py       7 secure counterpart endpoints
│   │   └── routes_reports.py      /reports/findings.json and .md
│   ├── core/config.py             pydantic-settings (APPSEC_ env prefix)
│   ├── db/                        SQLite schema + init + seed
│   ├── models/schemas.py          Finding, AppSecReport, User, Note, Comment
│   └── services/
│       ├── sast_checks.py         Regex pattern scanner for Python source
│       ├── dast_checks.py         In-process payload checks via httpx
│       └── report_service.py      Markdown + JSON report generation
└── tests/                         151 tests across 8 modules
```

## Request flow

```
Test / API client
      ↓
FastAPI app (create_app)
      ↓
routes_vulnerable.py  ←→  intentionally flawed logic
routes_secure.py      ←→  correct mitigations applied
      ↓
SQLite (per-test isolated DB via tmp_path)
```

## App factory

`create_app(db_path)` takes an optional `db_path`. Tests pass a `tmp_path`-based path for isolation. The lifespan context manager runs `init_db` and `seed_db` on startup.

## Storage

SQLite via the standard `sqlite3` module (synchronous). FastAPI runs sync route handlers in a thread pool. Appropriate for a single-user lab — documented in this file as an intentional trade-off.

Tables: `users`, `notes`, `comments`, `uploaded_files`.

## Test strategy

- All tests use `TestClient(app)` with a fresh per-test SQLite database.
- No mocks — all storage is real SQLite, all endpoints are exercised end-to-end.
- DAST checks (`dast_checks.py`) send real payloads to the in-process app and interpret responses.
- SAST checks (`sast_checks.py`) scan actual source files on disk.
