# Remediation Guide

Step-by-step remediation for each finding. Each step references the secure implementation in `app/api/routes_secure.py`.

---

## FIND-001 — SQL Injection

**Severity:** High | **CWE:** CWE-89

### Step 1: Identify all SQL-building code

Search for `f"`, `%`, `.format(` in files that touch database queries.

### Step 2: Replace with parameterized queries

```python
# Before
query = f"SELECT * FROM notes WHERE title LIKE '%{q}%'"
conn.execute(query)

# After
conn.execute("SELECT * FROM notes WHERE title LIKE ?", (f"%{q}%",))
```

### Step 3: Use an ORM with parameterization by default

SQLAlchemy, Tortoise ORM, and Django ORM all use bound parameters unless explicitly overridden with `.raw()`.

### Step 4: Verify

Write a test that sends `' OR '1'='1` and asserts it returns 0 rows, not all rows.

---

## FIND-002 — IDOR

**Severity:** High | **CWE:** CWE-639

### Step 1: Remove user_id from path/query parameters

Any resource lookup that depends on user identity must get that identity from the verified auth token, not from the request.

### Step 2: Add ownership constraint to all queries

```python
conn.execute(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?",
    (note_id, current_user_id),
)
```

### Step 3: Return 404, not 403

Returning 403 leaks that the resource exists. Return 404 for unauthorized access to avoid enumeration.

### Step 4: Verify

Write a test where user A requests a resource belonging to user B and asserts 404.

---

## FIND-003 — Weak JWT

**Severity:** Critical | **CWE:** CWE-287, CWE-347

### Step 1: Generate a strong secret

```python
import secrets
JWT_SECRET = secrets.token_hex(32)    # 256-bit random key
```

Store it in environment config, never in source code.

### Step 2: Always include exp claim

```python
from datetime import datetime, timedelta, timezone
exp = datetime.now(timezone.utc) + timedelta(minutes=30)
jwt.encode({**payload, "exp": exp}, secret, algorithm="HS256")
```

### Step 3: Do not disable expiry verification

Remove any `options={"verify_exp": False}` from `jwt.decode()` calls.

### Step 4: Verify

Write a test that uses a token with `exp` set to one hour in the past and asserts 401.

---

## FIND-004 — SSRF

**Severity:** High | **CWE:** CWE-918

### Step 1: Validate scheme

Only allow `http` and `https`.

### Step 2: Resolve hostname and check IP range

```python
import ipaddress, socket
resolved = socket.getaddrinfo(hostname, None)
for *_, sockaddr in resolved:
    addr = ipaddress.ip_address(sockaddr[0])
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError(f"blocked: {addr}")
```

### Step 3: Do not follow redirects without re-validation

`follow_redirects=False` unless you re-validate the redirect target.

### Step 4: Consider an allowlist

If the set of valid external targets is known, maintain an allowlist of domains.

### Step 5: Verify

Write tests for `http://127.0.0.1/`, `http://192.168.x.x/`, `file://`, `ftp://` all returning 400.

---

## FIND-005 — Stored XSS

**Severity:** High | **CWE:** CWE-79

### Step 1: Escape before inserting into HTML

```python
import html
escaped = html.escape(user_input)
rendered = f"<p>{escaped}</p>"
```

### Step 2: Add Content-Security-Policy header

```python
return HTMLResponse(content=body, headers={"Content-Security-Policy": "default-src 'self'"})
```

### Step 3: Use a templating engine with auto-escaping

Jinja2 with `autoescape=True` or similar.

### Step 4: Verify

Send `<script>alert('xss')</script>` and assert `<script>` is not in the stored `rendered_html`.

---

## FIND-006 — Insecure File Upload

**Severity:** High | **CWE:** CWE-434, CWE-22

### Step 1: Enforce extension whitelist

```python
ALLOWED = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".csv"}
if Path(file.filename).suffix.lower() not in ALLOWED:
    raise HTTPException(400, "file type not allowed")
```

### Step 2: Randomize stored filename

```python
import uuid
stored_name = f"{uuid.uuid4().hex}{suffix}"
```

### Step 3: Enforce size limit

```python
content = await file.read()
if len(content) > MAX_BYTES:
    raise HTTPException(413, "file too large")
```

### Step 4: Verify

Test that `.php`, `.exe`, `.sh` files return 400. Test that `../../etc/passwd.txt` is stored as a UUID filename with no path separators.

---

## FIND-007 — Security Misconfiguration

**Severity:** High | **CWE:** CWE-200

### Step 1: Remove or disable debug endpoints

```python
@app.get("/debug")
def debug():
    raise HTTPException(404)
```

### Step 2: Never return exception details to clients

Set `debug=False` in FastAPI and ensure exception handlers return only safe messages.

### Step 3: Audit environment variable exposure

Review all routes that call `os.environ` or `settings.*` and confirm none expose secrets.

### Step 4: Verify

Request `GET /debug` and assert 404.
