"""
Secure counterparts to the vulnerable endpoints in routes_vulnerable.py.
Each demonstrates the correct mitigation for the corresponding vulnerability.
"""
import hashlib
import html
import ipaddress
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import Settings
from app.db.database import get_connection
from app.models.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/secure", tags=["secure"])

_ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".csv"}
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _get_db(request: Request) -> sqlite3.Connection:
    return get_connection(request.app.state.db_path)


def _require_auth(request: Request) -> dict:
    settings = _get_settings(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# ── 1. SQL Injection (secure) ─────────────────────────────────────────────────

@router.get("/search")
def secure_search(q: str, request: Request):
    """Parameterized query — SQL injection not possible."""
    conn = _get_db(request)
    rows = conn.execute(
        "SELECT id, title, content FROM notes WHERE title LIKE ?",
        (f"%{q}%",),
    ).fetchall()
    return [dict(r) for r in rows]


# ── 2. IDOR (secure) ─────────────────────────────────────────────────────────

@router.get("/notes/{note_id}")
def secure_get_note(note_id: int, request: Request):
    """Ownership enforced from JWT — IDOR not possible."""
    user = _require_auth(request)
    conn = _get_db(request)
    row = conn.execute(
        "SELECT id, user_id, title, content FROM notes WHERE id = ? AND user_id = ?",
        (note_id, int(user["sub"])),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


# ── 3. Secure JWT ─────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def secure_login(body: LoginRequest, request: Request):
    """JWT signed with strong secret, short expiry enforced."""
    settings = _get_settings(request)
    conn = _get_db(request)
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (body.username,),
    ).fetchone()
    if row is None or not _pwd_ctx.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    token = jwt.encode(
        {"sub": str(row["id"]), "username": row["username"], "exp": exp},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    return TokenResponse(access_token=token)


@router.get("/me")
def secure_me(request: Request):
    """Validates JWT signature and expiry before trusting claims."""
    user = _require_auth(request)
    return {"user_id": user.get("sub"), "username": user.get("username")}


# ── 4. SSRF (secure) ─────────────────────────────────────────────────────────

def _is_safe_url(url: str) -> tuple[bool, str]:
    """Returns (is_safe, reason). Blocks RFC1918, loopback, and link-local."""
    try:
        parsed = httpx.URL(url)
    except Exception:
        return False, "invalid URL"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme '{parsed.scheme}' not allowed"

    host = parsed.host
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False, f"IP {addr} is in a blocked range"
    except ValueError:
        # hostname — resolve and check
        import socket
        try:
            resolved = socket.getaddrinfo(host, None)
            for *_, sockaddr in resolved:
                try:
                    addr = ipaddress.ip_address(sockaddr[0])
                    if addr.is_private or addr.is_loopback or addr.is_link_local:
                        return False, f"hostname {host} resolves to blocked IP {addr}"
                except ValueError:
                    pass
        except socket.gaierror:
            return False, f"hostname '{host}' could not be resolved"

    return True, ""


@router.get("/fetch")
def secure_fetch(url: str):
    """SSRF guard: rejects private IPs, loopback, and non-HTTP(S) schemes."""
    safe, reason = _is_safe_url(url)
    if not safe:
        raise HTTPException(status_code=400, detail=f"URL blocked: {reason}")
    try:
        resp = httpx.get(url, timeout=5, follow_redirects=False)
        return {"status_code": resp.status_code, "body": resp.text[:2000]}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── 5. XSS (secure) ──────────────────────────────────────────────────────────

@router.post("/comments")
def secure_post_comment(request: Request, content: str):
    """HTML entities escaped before storage — XSS not possible."""
    conn = _get_db(request)
    escaped = html.escape(content)
    rendered = f"<p>{escaped}</p>"
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
def secure_render_comments(request: Request):
    """Rendered HTML is already escaped at storage time."""
    conn = _get_db(request)
    rows = conn.execute("SELECT id, content, rendered_html FROM comments").fetchall()
    combined = "\n".join(r["rendered_html"] for r in rows)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=f"<html><body>{combined}</body></html>",
                        headers={"Content-Security-Policy": "default-src 'self'"})


# ── 6. Secure File Upload ─────────────────────────────────────────────────────

@router.post("/upload")
async def secure_upload(file: UploadFile, request: Request):
    """Extension whitelist, size limit, randomized stored filename."""
    settings = _get_settings(request)

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{suffix}' not allowed. Allowed: {sorted(_ALLOWED_EXTENSIONS)}",
        )

    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large (max 1 MB)")

    # Randomized stored name prevents path traversal and filename enumeration
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / stored_name
    dest.write_bytes(content)

    conn = _get_db(request)
    conn.execute(
        "INSERT INTO uploaded_files (original_name, stored_name, file_type, uploaded_at) "
        "VALUES (?, ?, ?, ?)",
        (file.filename, stored_name, suffix,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return {"stored_as": stored_name, "size": len(content), "original": file.filename}


# ── 7. Security Misconfiguration (secure) ────────────────────────────────────

@router.get("/debug")
def secure_debug():
    """Debug endpoint disabled — returns 404 in any deployment."""
    raise HTTPException(status_code=404, detail="Not found")
