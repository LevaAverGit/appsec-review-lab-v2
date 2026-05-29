import time
import pytest
import httpx
from jose import jwt


class TestJWT:
    # Vulnerable login / me

    def test_vulnerable_login_success(self, client: httpx.Client):
        resp = client.post(
            "/vulnerable/login", json={"username": "alice", "password": "password123"}
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_vulnerable_login_bad_password(self, client: httpx.Client):
        resp = client.post(
            "/vulnerable/login", json={"username": "alice", "password": "wrong"}
        )
        assert resp.status_code == 401

    def test_vulnerable_login_unknown_user(self, client: httpx.Client):
        resp = client.post(
            "/vulnerable/login", json={"username": "nobody", "password": "x"}
        )
        assert resp.status_code == 401

    def test_vulnerable_me_accepts_forged_token(self, client: httpx.Client):
        forged = jwt.encode({"sub": "999", "username": "attacker"}, "secret", algorithm="HS256")
        resp = client.get("/vulnerable/me", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "attacker"

    def test_vulnerable_me_accepts_expired_token(self, client: httpx.Client):
        exp_past = int(time.time()) - 7200
        token = jwt.encode(
            {"sub": "1", "username": "alice", "exp": exp_past}, "secret", algorithm="HS256"
        )
        resp = client.get("/vulnerable/me", headers={"Authorization": f"Bearer {token}"})
        # Vulnerable endpoint ignores expiry
        assert resp.status_code == 200

    def test_vulnerable_me_no_token_returns_401(self, client: httpx.Client):
        resp = client.get("/vulnerable/me")
        assert resp.status_code == 401

    # Secure login / me

    def test_secure_login_success(self, client: httpx.Client):
        resp = client.post(
            "/secure/login", json={"username": "alice", "password": "password123"}
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_secure_login_bad_password(self, client: httpx.Client):
        resp = client.post(
            "/secure/login", json={"username": "alice", "password": "wrong"}
        )
        assert resp.status_code == 401

    def test_secure_login_unknown_user(self, client: httpx.Client):
        resp = client.post(
            "/secure/login", json={"username": "nobody", "password": "x"}
        )
        assert resp.status_code == 401

    def test_secure_me_success(self, client: httpx.Client, alice_token: str):
        resp = client.get(
            "/secure/me", headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_secure_me_no_token_returns_401(self, client: httpx.Client):
        resp = client.get("/secure/me")
        assert resp.status_code == 401

    def test_secure_me_rejects_forged_token(self, client: httpx.Client):
        forged = jwt.encode({"sub": "999", "username": "attacker"}, "wrong_secret", algorithm="HS256")
        resp = client.get("/secure/me", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401

    def test_secure_me_rejects_expired_token(self, client: httpx.Client):
        exp_past = int(time.time()) - 7200
        token = jwt.encode(
            {"sub": "1", "username": "alice", "exp": exp_past},
            "FAKE_JWT_SECRET_FOR_LAB_ONLY_NOT_FOR_PRODUCTION",
            algorithm="HS256",
        )
        resp = client.get("/secure/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_secure_token_contains_username(self, client: httpx.Client):
        resp = client.post(
            "/secure/login", json={"username": "bob", "password": "hunter2"}
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        payload = jwt.decode(
            token,
            "FAKE_JWT_SECRET_FOR_LAB_ONLY_NOT_FOR_PRODUCTION",
            algorithms=["HS256"],
        )
        assert payload["username"] == "bob"

    def test_secure_token_has_exp_claim(self, client: httpx.Client):
        resp = client.post(
            "/secure/login", json={"username": "alice", "password": "password123"}
        )
        token = resp.json()["access_token"]
        payload = jwt.decode(
            token,
            "FAKE_JWT_SECRET_FOR_LAB_ONLY_NOT_FOR_PRODUCTION",
            algorithms=["HS256"],
        )
        assert "exp" in payload
        assert payload["exp"] > int(time.time())
