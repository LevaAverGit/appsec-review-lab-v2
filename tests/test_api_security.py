"""Tests for the API-security findings (OWASP API Security Top 10 2023).

Covers Broken Function Level Authorization (BFLA, API5) and Mass Assignment /
BOPLA (API3) — the vulnerable endpoints escalate privilege, the secure ones do not.
"""


# ── BFLA (API5:2023) ─────────────────────────────────────────────────────────

def test_bfla_vulnerable_lists_users_without_auth(client):
    resp = client.get("/vulnerable/admin/users")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1  # seeded users are exposed to anyone


def test_bfla_secure_rejects_unauthenticated(client):
    resp = client.get("/secure/admin/users")
    assert resp.status_code == 401


def test_bfla_secure_rejects_non_admin(client, bob_token):
    resp = client.get("/secure/admin/users", headers={"Authorization": f"Bearer {bob_token}"})
    assert resp.status_code == 403


def test_bfla_secure_allows_admin(client, alice_token):
    resp = client.get("/secure/admin/users", headers={"Authorization": f"Bearer {alice_token}"})
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


# ── Mass Assignment / BOPLA (API3:2023) ──────────────────────────────────────

def test_mass_assignment_vulnerable_allows_role_escalation(client):
    resp = client.post("/vulnerable/profile", json={"username": "eve", "role": "admin"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"  # escalated via mass assignment


def test_mass_assignment_secure_ignores_privileged_field(client):
    resp = client.post(
        "/secure/profile",
        json={"username": "eve", "role": "admin", "display_name": "Eve"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "user"          # privileged field ignored
    assert body["display_name"] == "Eve"   # whitelisted field applied
