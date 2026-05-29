import pytest
import httpx


class TestSSRF:
    # Vulnerable endpoint — demonstrates SSRF via simulated internal responses

    def test_vulnerable_fetch_returns_simulated_internal(self, client: httpx.Client):
        resp = client.get("/vulnerable/fetch", params={"url": "http://127.0.0.1/admin"})
        assert resp.status_code == 200
        assert "LAB SIMULATION" in resp.json()["body"]

    def test_vulnerable_fetch_ec2_metadata_simulated(self, client: httpx.Client):
        resp = client.get(
            "/vulnerable/fetch",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert resp.status_code == 200
        assert "LAB SIMULATION" in resp.json()["body"]

    def test_vulnerable_fetch_internal_service_simulated(self, client: httpx.Client):
        resp = client.get(
            "/vulnerable/fetch",
            params={"url": "http://internal.service.local/config"},
        )
        assert resp.status_code == 200
        assert "LAB SIMULATION" in resp.json()["body"]

    def test_vulnerable_fetch_unknown_url_rejected(self, client: httpx.Client):
        # Non-demo URL is rejected — endpoint is lab-only, not a public proxy
        resp = client.get("/vulnerable/fetch", params={"url": "http://example.com/"})
        assert resp.status_code == 400
        assert "demo" in resp.json()["detail"].lower()

    def test_vulnerable_fetch_no_guard_hint_in_body(self, client: httpx.Client):
        # The vulnerable endpoint has no IP guard — demonstrated by returning
        # simulated internal content without any validation
        resp = client.get("/vulnerable/fetch", params={"url": "http://127.0.0.1/admin"})
        assert resp.status_code == 200

    def test_vulnerable_fetch_no_real_http_request(self, client: httpx.Client, monkeypatch):
        """Vulnerable endpoint must never make a real outbound HTTP call."""
        def _fail(*args, **kwargs):
            raise AssertionError("vulnerable fetch made a real HTTP request")

        monkeypatch.setattr(httpx, "get", _fail)
        resp = client.get("/vulnerable/fetch", params={"url": "http://127.0.0.1/admin"})
        assert resp.status_code == 200
        assert "LAB SIMULATION" in resp.json()["body"]

    def test_vulnerable_fetch_arbitrary_external_rejected(self, client: httpx.Client):
        resp = client.get(
            "/vulnerable/fetch", params={"url": "http://attacker.example.com/steal"}
        )
        assert resp.status_code == 400
        assert "predefined lab SSRF demo targets" in resp.json()["detail"]

    # Secure endpoint — SSRF guard tests

    def test_secure_blocks_loopback_ip(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://127.0.0.1/"})
        assert resp.status_code == 400
        assert "blocked" in resp.json()["detail"].lower()

    def test_secure_blocks_localhost(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://localhost/admin"})
        assert resp.status_code == 400

    def test_secure_blocks_private_rfc1918_192(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://192.168.1.1/"})
        assert resp.status_code == 400

    def test_secure_blocks_private_rfc1918_10(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://10.0.0.1/"})
        assert resp.status_code == 400

    def test_secure_blocks_private_rfc1918_172(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://172.16.0.1/"})
        assert resp.status_code == 400

    def test_secure_blocks_file_scheme(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "file:///etc/passwd"})
        assert resp.status_code == 400

    def test_secure_blocks_ftp_scheme(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "ftp://example.com/file"})
        assert resp.status_code == 400

    def test_secure_invalid_url_rejected(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "not-a-url"})
        assert resp.status_code == 400

    def test_secure_blocks_0000(self, client: httpx.Client):
        resp = client.get("/secure/fetch", params={"url": "http://0.0.0.0/"})
        assert resp.status_code == 400

    def test_ssrf_is_safe_url_helper_loopback(self):
        from app.api.routes_secure import _is_safe_url
        safe, reason = _is_safe_url("http://127.0.0.1/")
        assert not safe
        assert "blocked" in reason.lower()

    def test_ssrf_is_safe_url_helper_private(self):
        from app.api.routes_secure import _is_safe_url
        safe, reason = _is_safe_url("http://192.168.0.1/")
        assert not safe

    def test_ssrf_is_safe_url_helper_valid_scheme(self):
        from app.api.routes_secure import _is_safe_url
        safe, _ = _is_safe_url("file:///etc/passwd")
        assert not safe

    def test_ssrf_is_safe_url_helper_returns_tuple(self):
        from app.api.routes_secure import _is_safe_url
        result = _is_safe_url("http://127.0.0.1/")
        assert isinstance(result, tuple)
        assert len(result) == 2
        safe, reason = result
        assert isinstance(safe, bool)
        assert isinstance(reason, str)
