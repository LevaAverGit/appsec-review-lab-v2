# Demo — proof of run

Reproduce locally (no server or network needed — runs in-process against a
throwaway temp DB):

```bash
pip install -r requirements-dev.txt
python scripts/demo.py
```

The script ([scripts/demo.py](../scripts/demo.py)) exercises the vulnerable and
secure endpoint pairs side by side and runs the SAST scanner. Captured output:

```text
======================================================================
1. SQL Injection (A03) - vulnerable vs secure
======================================================================
  vulnerable /search q="' OR 1=1 -- " -> rows returned: 4 (all notes leaked)
  secure     /search q="' OR 1=1 -- " -> rows returned: 0 (treated as literal)

======================================================================
2. Cryptographic Failures (A02) - password hashing
======================================================================
  vulnerable /register -> {'username': 'demo_v', 'algorithm': 'md5', 'password_hash': '195f19b835efe9f0b7b4e276ef1a8515'}
  secure     /register -> {'username': 'demo_s', 'algorithm': 'bcrypt'}

======================================================================
3. Broken Function Level Authorization / BFLA (API5)
======================================================================
  vulnerable /admin/users (no auth) -> HTTP 200
  secure     /admin/users (no auth) -> HTTP 401

======================================================================
4. Mass Assignment / BOPLA (API3)
======================================================================
  vulnerable /profile {role: admin} -> resulting role: admin
  secure     /profile {role: admin} -> resulting role: user

======================================================================
5. SAST scan of routes_vulnerable.py
======================================================================
  [high    ] SQL_INJECTION_FSTRING    CWE-89  (line 38)
  [high    ] HARDCODED_SECRET         CWE-798  (line 63)
  [critical] JWT_WEAK_OPTIONS         CWE-347  (line 99)
  [medium  ] SSRF_UNCHECKED_REQUEST   CWE-918  (line 143)
  [high    ] XSS_RAW_HTML             CWE-79  (line 160)
  [high    ] XSS_RAW_HTML             CWE-79  (line 180)
  [medium  ] DEBUG_ENDPOINT_ENV_DUMP  CWE-200  (line 218)
  [high    ] WEAK_PASSWORD_HASH       CWE-916  (line 238)
  total findings: 8
```

## What this shows

| # | Risk | Vulnerable result | Secure result |
|---|------|-------------------|---------------|
| 1 | SQL Injection (A03) | `' OR 1=1 --` leaks all 4 notes | parameterized query returns 0 |
| 2 | Cryptographic Failures (A02) | unsalted MD5, digest leaked | bcrypt, hash never returned |
| 3 | BFLA (API5) | admin listing served to anyone (200) | unauthenticated request rejected (401) |
| 4 | Mass Assignment (API3) | client sets `role: admin` | privileged field ignored, stays `user` |
| 5 | SAST | 8 findings flagged in the vulnerable routes, CWE-tagged | — |

To explore interactively, run the API and open the Swagger UI:

```bash
uvicorn app.main:app --reload
# then browse http://127.0.0.1:8000/docs
```
