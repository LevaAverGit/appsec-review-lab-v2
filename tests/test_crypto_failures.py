"""Tests for OWASP A02:2021 Cryptographic Failures (vulnerable vs secure).

The vulnerable endpoint stores passwords with unsalted MD5 and leaks the digest;
the secure endpoint uses bcrypt and never returns the hash.
"""
import hashlib
from pathlib import Path

from app.services.sast_checks import scan_file


def test_vulnerable_register_uses_unsalted_md5(client):
    resp = client.post("/vulnerable/register", json={"username": "eve_md5", "password": "pw"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["algorithm"] == "md5"
    # Unsalted MD5 is deterministic — the leaked digest is trivially reproducible
    assert body["password_hash"] == hashlib.md5(b"pw").hexdigest()


def test_secure_register_uses_bcrypt_and_hides_hash(client):
    resp = client.post("/secure/register", json={"username": "eve_bcrypt", "password": "pw"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["algorithm"] == "bcrypt"
    # The hash must never be returned to the client
    assert "password_hash" not in body


def test_secure_register_produces_salted_digest_and_allows_login(client):
    client.post("/secure/register", json={"username": "carol", "password": "s3cret!"})
    resp = client.post("/secure/login", json={"username": "carol", "password": "s3cret!"})
    assert resp.status_code == 200, resp.text
    assert "access_token" in resp.json()


def test_duplicate_registration_returns_conflict(client):
    client.post("/secure/register", json={"username": "dup", "password": "x"})
    resp = client.post("/secure/register", json={"username": "dup", "password": "x"})
    assert resp.status_code == 409


def test_sast_flags_weak_hash_in_vulnerable_routes():
    routes = Path(__file__).parents[1] / "app" / "api" / "routes_vulnerable.py"
    findings = scan_file(routes)
    assert any(f.pattern == "WEAK_PASSWORD_HASH" for f in findings)


def test_sast_does_not_flag_weak_hash_in_secure_routes():
    routes = Path(__file__).parents[1] / "app" / "api" / "routes_secure.py"
    findings = scan_file(routes)
    assert not any(f.pattern == "WEAK_PASSWORD_HASH" for f in findings)
