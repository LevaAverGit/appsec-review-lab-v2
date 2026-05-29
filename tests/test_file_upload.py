import io
import pytest
import httpx


def _upload(client: httpx.Client, endpoint: str, filename: str, content: bytes = b"test") -> httpx.Response:
    return client.post(
        endpoint,
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
    )


class TestFileUpload:
    # Vulnerable endpoint — demonstrates the issues

    def test_vulnerable_accepts_php_file(self, client: httpx.Client):
        resp = _upload(client, "/vulnerable/upload", "shell.php", b"<?php system($_GET['cmd']); ?>")
        assert resp.status_code == 200

    def test_vulnerable_accepts_exe_file(self, client: httpx.Client):
        resp = _upload(client, "/vulnerable/upload", "malware.exe", b"MZ\x90\x00")
        assert resp.status_code == 200

    def test_vulnerable_accepts_any_extension(self, client: httpx.Client):
        resp = _upload(client, "/vulnerable/upload", "file.sh", b"#!/bin/bash\nrm -rf /")
        assert resp.status_code == 200

    def test_vulnerable_returns_stored_path(self, client: httpx.Client):
        resp = _upload(client, "/vulnerable/upload", "test.txt", b"content")
        assert resp.status_code == 200
        assert "stored_as" in resp.json()

    # Secure endpoint — demonstrates mitigations

    def test_secure_rejects_php(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "shell.php", b"<?php ?>")
        assert resp.status_code == 400
        assert "not allowed" in resp.json()["detail"].lower()

    def test_secure_rejects_exe(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "malware.exe", b"MZ\x90\x00")
        assert resp.status_code == 400

    def test_secure_rejects_sh(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "evil.sh", b"#!/bin/bash")
        assert resp.status_code == 400

    def test_secure_rejects_js(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "script.js", b"alert(1)")
        assert resp.status_code == 400

    def test_secure_accepts_txt(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "readme.txt", b"safe text")
        assert resp.status_code == 200

    def test_secure_accepts_pdf(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "doc.pdf", b"%PDF-1.4 fake")
        assert resp.status_code == 200

    def test_secure_accepts_png(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "image.png", b"\x89PNG\r\n\x1a\n")
        assert resp.status_code == 200

    def test_secure_accepts_csv(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "data.csv", b"col1,col2\n1,2")
        assert resp.status_code == 200

    def test_secure_randomizes_stored_name(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "readme.txt", b"content")
        assert resp.status_code == 200
        stored = resp.json()["stored_as"]
        assert stored != "readme.txt"
        assert stored.endswith(".txt")

    def test_secure_no_path_traversal_in_stored_name(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "../../etc/passwd.txt", b"content")
        assert resp.status_code == 200
        stored = resp.json()["stored_as"]
        assert "/" not in stored
        assert ".." not in stored

    def test_secure_rejects_oversized_file(self, client: httpx.Client):
        big = b"x" * (1_048_576 + 1)  # 1 MB + 1 byte
        resp = _upload(client, "/secure/upload", "big.txt", big)
        assert resp.status_code == 413

    def test_secure_returns_original_filename(self, client: httpx.Client):
        resp = _upload(client, "/secure/upload", "myfile.txt", b"data")
        assert resp.status_code == 200
        assert resp.json()["original"] == "myfile.txt"

    def test_secure_no_filename_returns_error(self, client: httpx.Client):
        resp = client.post(
            "/secure/upload",
            files={"file": ("", io.BytesIO(b"data"), "text/plain")},
        )
        # 400 from our handler or 422 from FastAPI multipart validation — both are client errors
        assert resp.status_code in (400, 422)
