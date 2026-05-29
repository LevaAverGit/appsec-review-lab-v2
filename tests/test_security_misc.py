import pytest
import httpx


class TestSecurityMisc:
    def test_vulnerable_debug_returns_200(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200

    def test_vulnerable_debug_exposes_jwt_secret(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert "jwt_secret" in data

    def test_vulnerable_debug_exposes_db_path(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200
        assert "db_path" in resp.json()

    def test_vulnerable_debug_exposes_env_vars(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200
        assert "env_vars" in resp.json()
        assert isinstance(resp.json()["env_vars"], dict)

    def test_vulnerable_debug_exposes_upload_dir(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200
        assert "upload_dir" in resp.json()

    def test_vulnerable_debug_exposes_python_path(self, client: httpx.Client):
        resp = client.get("/vulnerable/debug")
        assert resp.status_code == 200
        assert "python_path" in resp.json()

    def test_secure_debug_returns_404(self, client: httpx.Client):
        resp = client.get("/secure/debug")
        assert resp.status_code == 404

    def test_secure_debug_no_secrets_in_response(self, client: httpx.Client):
        resp = client.get("/secure/debug")
        assert "jwt_secret" not in resp.text
        assert "password" not in resp.text.lower()

    def test_health_endpoint_returns_ok(self, client: httpx.Client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
