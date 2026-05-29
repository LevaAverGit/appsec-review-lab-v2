# Secure Code Review Guide

This guide explains the specific code patterns that create each vulnerability and the corresponding fix. Use it as a reference when reviewing Python/FastAPI code.

---

## 1. SQL Injection (CWE-89)

### Vulnerable pattern

```python
# f-string or % or .format() in a SQL query
query = f"SELECT * FROM notes WHERE title LIKE '%{q}%'"
conn.execute(query)
```

### What to look for in review

- Any f-string, `.format()`, or `%` formatting touching SQL
- `cursor.execute(sql)` where `sql` is built by concatenation
- ORM raw queries with `.raw(f"...")` or `text(f"...")`

### Secure pattern

```python
conn.execute("SELECT * FROM notes WHERE title LIKE ?", (f"%{q}%",))
```

---

## 2. IDOR (CWE-639)

### Vulnerable pattern

```python
# User identity from query param, not from auth token
def get_note(note_id: int, user_id: int):  # user_id from request
    conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
```

### What to look for in review

- `user_id`, `account_id`, `owner_id` taken from path/query params
- Missing `AND owner = ?` in queries that access user-owned resources
- Authorization checks that compare user-supplied values against DB

### Secure pattern

```python
def get_note(note_id: int, request: Request):
    user = _require_auth(request)          # identity from verified JWT
    conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, int(user["sub"])),
    )
```

---

## 3. Weak JWT (CWE-287, CWE-347)

### Vulnerable patterns

```python
# Hardcoded secret
jwt.encode(payload, "secret", algorithm="HS256")

# Expiry not enforced
jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})
```

### What to look for in review

- String literals as JWT secrets
- `verify_exp: False` or missing `exp` claim generation
- Algorithm `none` or `HS256` without secret rotation strategy
- JWT decoded without catching `ExpiredSignatureError`

### Secure pattern

```python
secret = settings.jwt_secret          # from environment config
exp = datetime.now(timezone.utc) + timedelta(minutes=30)
jwt.encode({**payload, "exp": exp}, secret, algorithm="HS256")

# Decode with default options (expiry enforced)
jwt.decode(token, secret, algorithms=["HS256"])
```

---

## 4. SSRF (CWE-918)

### Vulnerable pattern

```python
resp = httpx.get(url)       # url from user — no validation
```

### What to look for in review

- `requests.get(url)`, `httpx.get(url)`, `urllib.request.urlopen(url)` where `url` is user-controlled
- Missing hostname resolution + RFC1918/loopback check
- Redirect following without host re-validation

### Secure pattern

```python
def _is_safe_url(url: str) -> tuple[bool, str]:
    parsed = httpx.URL(url)
    if parsed.scheme not in ("http", "https"):
        return False, "scheme not allowed"
    addr = ipaddress.ip_address(parsed.host)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False, f"IP {addr} is in a blocked range"
    return True, ""
```

---

## 5. Stored XSS (CWE-79)

### Vulnerable pattern

```python
rendered = f"<p>{content}</p>"   # raw user content in HTML
```

### What to look for in review

- Any f-string, `.format()`, or `+` concatenation building HTML with user input
- Jinja2/Mako templates with `| safe` filter on user content
- `innerHTML =` in JavaScript with server-supplied values

### Secure pattern

```python
import html
escaped = html.escape(content)
rendered = f"<p>{escaped}</p>"
```

Also add: `Content-Security-Policy: default-src 'self'` response header.

---

## 6. Insecure File Upload (CWE-434, CWE-22)

### Vulnerable patterns

```python
dest = upload_dir / file.filename        # path traversal
dest.write_bytes(content)                # no size check, no type check
```

### What to look for in review

- Original filename used in filesystem path
- No extension whitelist
- No content-type or magic byte validation
- No file size limit
- Upload directory inside web root

### Secure pattern

```python
suffix = Path(file.filename).suffix.lower()
if suffix not in {".txt", ".pdf", ".png", ".jpg", ".csv"}:
    raise HTTPException(400, "file type not allowed")
content = await file.read()
if len(content) > 1_048_576:
    raise HTTPException(413, "file too large")
stored_name = f"{uuid.uuid4().hex}{suffix}"    # no original filename
dest = upload_dir / stored_name
```

---

## 7. Security Misconfiguration (CWE-200)

### Vulnerable pattern

```python
@app.get("/debug")
def debug():
    return {"env": os.environ, "secret": settings.jwt_secret}
```

### What to look for in review

- Debug endpoints not removed or protected
- Exception detail returned to API clients
- Stack traces in HTTP responses
- Secrets in log output

### Secure pattern

```python
@app.get("/debug")
def debug():
    raise HTTPException(status_code=404, detail="Not found")
```

And: disable `debug=True` in FastAPI/uvicorn for any shared deployment.
