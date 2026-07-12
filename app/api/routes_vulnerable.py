"""
Intentionally vulnerable endpoints for controlled lab demonstration.
These patterns represent common AppSec mistakes.
DO NOT deploy outside of an isolated lab environment.
"""
import hashlib
import html
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, UploadFile
from jose import jwt

from app.core.config import Settings
from app.db.database import get_connection
from app.models.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/vulnerable", tags=["vulnerable"])


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _get_db(request: Request) -> sqlite3.Connection:
    return get_connection(request.app.state.db_path)


# ── 1. SQL Injection ─────────────────────────────────────────────────────────

@router.get("/search")
def vulnerable_search(q: str, request: Request):
    """SQL Injection: user input interpolated directly into query string."""
    conn = _get_db(request)
    # VULNERABILITY: direct string interpolation → SQL injection
    query = f"SELECT id, title, content FROM notes WHERE title LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
    except (sqlite3.OperationalError, sqlite3.ProgrammingError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return [dict(r) for r in rows]


# ── 2. IDOR ───────────────────────────────────────────────────────────────────

@router.get("/notes/{note_id}")
def vulnerable_get_note(note_id: int, user_id: int, request: Request):
    """IDOR: user_id taken from query param, no ownership check."""
    conn = _get_db(request)
    # VULNERABILITY: user_id from query param, not from authenticated session
    row = conn.execute(
        "SELECT id, user_id, title, content FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


# ── 3. Weak JWT ───────────────────────────────────────────────────────────────

_WEAK_SECRET = "secret"  # hardcoded weak key


@router.post("/login", response_model=TokenResponse)
def vulnerable_login(body: LoginRequest, request: Request):
    """Weak JWT: signed with hardcoded 'secret', no expiry."""
    conn = _get_db(request)
    from passlib.context import CryptContext

    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (body.username,),
    ).fetchone()
    if row is None or not pwd_ctx.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # VULNERABILITY: weak hardcoded secret, no expiry
    token = jwt.encode(
        {"sub": str(row["id"]), "username": row["username"]},
        _WEAK_SECRET,
        algorithm="HS256",
    )
    return TokenResponse(access_token=token)


@router.get("/me")
def vulnerable_me(request: Request):
    """Weak JWT: accepts token signed with any secret, no expiry check."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1]
    try:
        # VULNERABILITY: options disable expiry check; weak secret assumed
        payload = jwt.decode(token, _WEAK_SECRET, algorithms=["HS256"],
                             options={"verify_exp": False})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"user_id": payload.get("sub"), "username": payload.get("username")}


# ── 4. SSRF ───────────────────────────────────────────────────────────────────

# Lab demo targets: simulated internal responses, no real HTTP requests are made.
# In a real SSRF scenario these would be live internal services.
_SSRF_DEMO_TARGETS: dict[str, dict] = {
    "http://127.0.0.1/admin": {
        "status_code": 200,
        "body": "[LAB SIMULATION] Admin panel at 127.0.0.1 — would be reachable via SSRF",
    },
    "http://169.254.169.254/latest/meta-data/": {
        "status_code": 200,
        "body": "[LAB SIMULATION] EC2 metadata: ami-id\ninstanceType\nlocal-ipv4\n",
    },
    "http://192.168.1.1/": {
        "status_code": 200,
        "body": "[LAB SIMULATION] Router management interface at 192.168.1.1",
    },
    "http://localhost/": {
        "status_code": 200,
        "body": "[LAB SIMULATION] Internal service on localhost",
    },
    "http://internal.service.local/config": {
        "status_code": 200,
        "body": "[LAB SIMULATION] Internal config service at internal.service.local — reachable via SSRF if DNS resolves internally",
    },
}

_SSRF_DEMO_HINT = (
    "Lab demo only. Use one of the predefined lab SSRF demo targets: "
    + ", ".join(_SSRF_DEMO_TARGETS.keys())
)


@router.get("/fetch")
def vulnerable_fetch(url: str):
    """SSRF demo: returns simulated internal-host responses for predefined lab URLs.

    VULNERABILITY demonstrated: no internal IP/scheme guard is applied before the request.
    In a real application with httpx.get(url), an attacker could reach internal services.
    Here the responses are simulated to keep the endpoint safe as a public demo.
    """
    if url not in _SSRF_DEMO_TARGETS:
        raise HTTPException(status_code=400, detail=_SSRF_DEMO_HINT)
    target = _SSRF_DEMO_TARGETS[url]
    # VULNERABILITY illustrated: no host/IP validation — any internal URL would be accepted
    return {"status_code": target["status_code"], "body": target["body"]}


# ── 5. XSS ────────────────────────────────────────────────────────────────────

@router.post("/comments")
def vulnerable_post_comment(request: Request, content: str):
    """XSS: stores raw content without HTML encoding."""
    conn = _get_db(request)
    # VULNERABILITY: content stored as raw HTML, no escaping
    rendered = f"<p>{content}</p>"
    conn.execute(
        "INSERT INTO comments (content, rendered_html) VALUES (?, ?)",
        (content, rendered),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id, content, rendered_html FROM comments ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return dict(row)


@router.get("/comments/rendered")
def vulnerable_render_comments(request: Request):
    """Returns raw HTML including any scripts stored by vulnerable_post_comment."""
    conn = _get_db(request)
    rows = conn.execute("SELECT id, content, rendered_html FROM comments").fetchall()
    # VULNERABILITY: rendered_html is served as HTML response with Content-Type text/html
    combined = "\n".join(r["rendered_html"] for r in rows)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=f"<html><body>{combined}</body></html>")


# ── 6. Insecure File Upload ───────────────────────────────────────────────────

@router.post("/upload")
async def vulnerable_upload(file: UploadFile, request: Request):
    """Insecure upload: no file type check, original filename used (path traversal)."""
    settings = _get_settings(request)
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)

    # VULNERABILITY: original filename used directly → path traversal possible
    dest = upload_dir / file.filename  # type: ignore[arg-type]
    content = await file.read()

    # VULNERABILITY: no size check, no extension whitelist, no content validation
    dest.write_bytes(content)

    conn = _get_db(request)
    conn.execute(
        "INSERT INTO uploaded_files (original_name, stored_name, file_type, uploaded_at) "
        "VALUES (?, ?, ?, ?)",
        (file.filename, str(dest), file.content_type or "unknown",
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return {"stored_as": str(dest), "size": len(content)}


# ── 7. Security Misconfiguration ─────────────────────────────────────────────

@router.get("/debug")
def vulnerable_debug(request: Request):
    """Security misconfiguration: exposes env vars, DB path, and internal config."""
    settings = _get_settings(request)
    # VULNERABILITY: exposes internal configuration and environment variables
    return {
        "env_vars": {k: v for k, v in os.environ.items() if not k.lower().startswith("home")},
        "db_path": settings.db_path,
        "jwt_secret": settings.jwt_secret,
        "upload_dir": settings.upload_dir,
        "python_path": os.sys.executable,
    }


# ── 8. Cryptographic Failures (A02) ──────────────────────────────────────────

@router.post("/register")
def vulnerable_register(body: LoginRequest, request: Request):
    """Cryptographic Failures: password stored with unsalted MD5.

    VULNERABILITY: MD5 is fast and unsalted, so the digest falls to rainbow-table
    and brute-force attacks in seconds. The stored hash is also echoed back,
    leaking the (weak) credential material.
    """
    conn = _get_db(request)
    # VULNERABILITY: MD5 is unsuitable for password storage (fast, unsalted, broken)
    weak_hash = hashlib.md5(body.password.encode()).hexdigest()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (body.username, weak_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    # VULNERABILITY: leaking the stored digest back to the client
    return {"username": body.username, "algorithm": "md5", "password_hash": weak_hash}
