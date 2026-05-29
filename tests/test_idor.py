import pytest
import httpx


class TestIDOR:
    # Note IDs in seed: 1→alice, 2→alice, 3→bob, 4→admin

    def test_vulnerable_own_note_accessible(self, client: httpx.Client):
        resp = client.get("/vulnerable/notes/1", params={"user_id": 1})
        assert resp.status_code == 200
        assert resp.json()["user_id"] == 1

    def test_vulnerable_cross_user_access(self, client: httpx.Client):
        # Alice (user_id=1) accessing Bob's note (note_id=3) — should be blocked but isn't
        resp = client.get("/vulnerable/notes/3", params={"user_id": 1})
        # IDOR: vulnerable endpoint returns 200 regardless of ownership
        assert resp.status_code == 200
        assert resp.json()["id"] == 3

    def test_vulnerable_admin_note_accessible_by_any_user(self, client: httpx.Client):
        # Admin note accessible by claiming user_id=1
        resp = client.get("/vulnerable/notes/4", params={"user_id": 1})
        assert resp.status_code == 200

    def test_vulnerable_nonexistent_note_returns_404(self, client: httpx.Client):
        resp = client.get("/vulnerable/notes/9999", params={"user_id": 1})
        assert resp.status_code == 404

    # Secure endpoint tests
    def test_secure_requires_auth(self, client: httpx.Client):
        resp = client.get("/secure/notes/1")
        assert resp.status_code == 401

    def test_secure_own_note_accessible(self, client: httpx.Client, alice_token: str):
        resp = client.get(
            "/secure/notes/1", headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["user_id"] == 1

    def test_secure_cross_user_access_blocked(self, client: httpx.Client, alice_token: str):
        # Alice tries to access Bob's note — should be 404
        resp = client.get(
            "/secure/notes/3", headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert resp.status_code == 404

    def test_secure_admin_note_not_accessible_by_alice(self, client: httpx.Client, alice_token: str):
        resp = client.get(
            "/secure/notes/4", headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert resp.status_code == 404

    def test_secure_bob_own_note_accessible(self, client: httpx.Client, bob_token: str):
        resp = client.get(
            "/secure/notes/3", headers={"Authorization": f"Bearer {bob_token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["user_id"] == 2

    def test_secure_bob_cannot_access_alice_note(self, client: httpx.Client, bob_token: str):
        resp = client.get(
            "/secure/notes/1", headers={"Authorization": f"Bearer {bob_token}"}
        )
        assert resp.status_code == 404

    def test_secure_nonexistent_note_returns_404(self, client: httpx.Client, alice_token: str):
        resp = client.get(
            "/secure/notes/9999", headers={"Authorization": f"Bearer {alice_token}"}
        )
        assert resp.status_code == 404
