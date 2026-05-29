import pytest
import httpx


XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<a href='javascript:void(0)' onclick='alert(1)'>click</a>",
]


class TestXSS:
    def test_vulnerable_stores_script_tag(self, client: httpx.Client):
        resp = client.post("/vulnerable/comments", params={"content": "<script>alert('xss')</script>"})
        assert resp.status_code == 200
        assert "<script>" in resp.json()["rendered_html"]

    def test_vulnerable_stores_img_onerror(self, client: httpx.Client):
        resp = client.post("/vulnerable/comments", params={"content": "<img src=x onerror=alert(1)>"})
        assert resp.status_code == 200
        assert "<img" in resp.json()["rendered_html"]

    def test_vulnerable_render_returns_html_content_type(self, client: httpx.Client):
        client.post("/vulnerable/comments", params={"content": "hello"})
        resp = client.get("/vulnerable/comments/rendered")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_vulnerable_script_appears_in_rendered_page(self, client: httpx.Client):
        client.post("/vulnerable/comments", params={"content": "<script>alert('xss')</script>"})
        resp = client.get("/vulnerable/comments/rendered")
        assert "<script>" in resp.text

    # Secure endpoint tests
    def test_secure_escapes_script_tag(self, client: httpx.Client):
        resp = client.post("/secure/comments", params={"content": "<script>alert('xss')</script>"})
        assert resp.status_code == 200
        rendered = resp.json()["rendered_html"]
        assert "<script>" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_secure_escapes_img_onerror(self, client: httpx.Client):
        resp = client.post("/secure/comments", params={"content": "<img src=x onerror=alert(1)>"})
        assert resp.status_code == 200
        rendered = resp.json()["rendered_html"]
        # The < and > are escaped — the img tag cannot execute in a browser
        assert "<img" not in rendered
        assert "&lt;img" in rendered

    def test_secure_preserves_plain_text(self, client: httpx.Client):
        resp = client.post("/secure/comments", params={"content": "Hello, world!"})
        assert resp.status_code == 200
        assert "Hello, world!" in resp.json()["rendered_html"]

    def test_secure_stores_original_content_unmodified(self, client: httpx.Client):
        payload = "<script>alert('xss')</script>"
        resp = client.post("/secure/comments", params={"content": payload})
        assert resp.status_code == 200
        # Original content is stored as-is; only rendered_html is escaped
        assert resp.json()["content"] == payload

    def test_secure_render_has_csp_header(self, client: httpx.Client):
        client.post("/secure/comments", params={"content": "test"})
        resp = client.get("/secure/comments/rendered")
        assert resp.status_code == 200
        assert "Content-Security-Policy" in resp.headers

    def test_secure_all_payloads_escaped(self, client: httpx.Client):
        for payload in XSS_PAYLOADS:
            resp = client.post("/secure/comments", params={"content": payload})
            assert resp.status_code == 200
            rendered = resp.json()["rendered_html"]
            # No unescaped HTML tags — the payload cannot execute in a browser
            assert "<script>" not in rendered
            assert "<img" not in rendered
            assert "<svg" not in rendered
