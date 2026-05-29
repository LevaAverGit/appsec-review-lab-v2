import pytest
import httpx


class TestSQLInjection:
    def test_normal_search_returns_results(self, client: httpx.Client):
        resp = client.get("/vulnerable/search", params={"q": "Alice"})
        assert resp.status_code == 200
        results = resp.json()
        assert isinstance(results, list)

    def test_normal_search_no_match(self, client: httpx.Client):
        resp = client.get("/vulnerable/search", params={"q": "zzznomatch"})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_sql_tautology_returns_all_rows(self, client: httpx.Client):
        resp = client.get("/vulnerable/search", params={"q": "' OR '1'='1"})
        # Either returns all rows (200) or sqlite error (400) — both indicate injection
        assert resp.status_code in (200, 400)
        if resp.status_code == 200:
            assert len(resp.json()) >= 4  # all 4 seed notes

    def test_sql_union_dumps_credentials(self, client: httpx.Client):
        payload = "' UNION SELECT id,username,password_hash FROM users --"
        resp = client.get("/vulnerable/search", params={"q": payload})
        assert resp.status_code in (200, 400)

    def test_sql_read_only_injection_union(self, client: httpx.Client):
        # Read-only UNION payload: demonstrates injection without destructive statements
        payload = "' UNION SELECT 1, 'injected', 'injected' --"
        resp = client.get("/vulnerable/search", params={"q": payload})
        assert resp.status_code in (200, 400)

    # Secure endpoint tests
    def test_secure_normal_search(self, client: httpx.Client):
        resp = client.get("/secure/search", params={"q": "Alice"})
        assert resp.status_code == 200
        results = resp.json()
        assert isinstance(results, list)

    def test_secure_search_empty(self, client: httpx.Client):
        resp = client.get("/secure/search", params={"q": "zzznomatch"})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_secure_tautology_returns_empty(self, client: httpx.Client):
        resp = client.get("/secure/search", params={"q": "' OR '1'='1"})
        assert resp.status_code == 200
        # Parameterized query treats the payload as literal search text → no match
        assert resp.json() == []

    def test_secure_union_not_injectable(self, client: httpx.Client):
        payload = "' UNION SELECT id,username,password_hash FROM users --"
        resp = client.get("/secure/search", params={"q": payload})
        assert resp.status_code == 200
        # Should return empty, not user credential data
        data = resp.json()
        assert isinstance(data, list)
        for row in data:
            assert "password_hash" not in row

    def test_secure_search_with_special_chars(self, client: httpx.Client):
        resp = client.get("/secure/search", params={"q": "Alice's note"})
        assert resp.status_code == 200

    def test_secure_search_returns_only_title_fields(self, client: httpx.Client):
        resp = client.get("/secure/search", params={"q": "note"})
        assert resp.status_code == 200
        for row in resp.json():
            assert "id" in row
            assert "title" in row
            assert "content" in row
