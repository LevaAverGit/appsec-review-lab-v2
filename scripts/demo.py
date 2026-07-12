"""Runnable proof-of-run demo: exercises vulnerable vs secure endpoints in-process.

    python scripts/demo.py

Uses FastAPI's TestClient against a throwaway temp DB — no server or network
needed. The captured output is checked into docs/DEMO.md.
"""
import sys
import tempfile
from pathlib import Path

# Allow `python scripts/demo.py` from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.db.database import init_db, seed_db
from app.main import create_app
from app.services.sast_checks import scan_file


def _client() -> TestClient:
    db = str(Path(tempfile.mkdtemp()) / "demo.db")
    init_db(db)
    seed_db(db)
    return TestClient(create_app(db_path=db))


def _section(title: str) -> None:
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


def main() -> None:
    c = _client()

    _section("1. SQL Injection (A03) - vulnerable vs secure")
    payload = "' OR 1=1 -- "
    print(f"  vulnerable /search q={payload!r} -> rows returned:",
          len(c.get("/vulnerable/search", params={"q": payload}).json()), "(all notes leaked)")
    print(f"  secure     /search q={payload!r} -> rows returned:",
          len(c.get("/secure/search", params={"q": payload}).json()), "(treated as literal)")

    _section("2. Cryptographic Failures (A02) - password hashing")
    v = c.post("/vulnerable/register", json={"username": "demo_v", "password": "p@ss"}).json()
    print("  vulnerable /register ->", v)
    s = c.post("/secure/register", json={"username": "demo_s", "password": "p@ss"}).json()
    print("  secure     /register ->", s)

    _section("3. Broken Function Level Authorization / BFLA (API5)")
    print("  vulnerable /admin/users (no auth) -> HTTP",
          c.get("/vulnerable/admin/users").status_code)
    print("  secure     /admin/users (no auth) -> HTTP",
          c.get("/secure/admin/users").status_code)

    _section("4. Mass Assignment / BOPLA (API3)")
    mv = c.post("/vulnerable/profile", json={"username": "eve", "role": "admin"}).json()
    print("  vulnerable /profile {role: admin} -> resulting role:", mv["role"])
    ms = c.post("/secure/profile", json={"username": "eve", "role": "admin"}).json()
    print("  secure     /profile {role: admin} -> resulting role:", ms["role"])

    _section("5. SAST scan of routes_vulnerable.py")
    findings = scan_file(Path("app/api/routes_vulnerable.py"))
    for f in findings:
        print(f"  [{f.severity:8}] {f.pattern:24} {f.cwe_id}  (line {f.line})")
    print(f"  total findings: {len(findings)}")


if __name__ == "__main__":
    main()
