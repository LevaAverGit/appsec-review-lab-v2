import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import create_app
from app.db.database import init_db, seed_db


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_db(path)
    seed_db(path)
    return path


@pytest.fixture
def client(db_path: str) -> TestClient:
    app = create_app(db_path=db_path)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def alice_token(client: TestClient) -> str:
    resp = client.post("/secure/login", json={"username": "alice", "password": "password123"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def bob_token(client: TestClient) -> str:
    resp = client.post("/secure/login", json={"username": "bob", "password": "hunter2"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]
