import sqlite3
from pathlib import Path

_SCHEMA = Path(__file__).parent / "schema.sql"


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str) -> None:
    conn = get_connection(db_path)
    conn.executescript(_SCHEMA.read_text())
    conn.commit()
    conn.close()


def seed_db(db_path: str) -> None:
    """Insert deterministic lab data for tests and demos."""
    from passlib.context import CryptContext

    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    conn = get_connection(db_path)

    users = [
        (1, "alice", pwd_ctx.hash("password123")),
        (2, "bob", pwd_ctx.hash("hunter2")),
        (3, "admin", pwd_ctx.hash("adminpass")),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?,?,?)",
        users,
    )

    notes = [
        (1, 1, "Alice's private note", "This is Alice's secret content."),
        (2, 1, "Another note by Alice", "More private content from Alice."),
        (3, 2, "Bob's note", "Bob's private data here."),
        (4, 3, "Admin credentials", "DB connection: sqlite:///lab.db"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO notes (id, user_id, title, content) VALUES (?,?,?,?)",
        notes,
    )

    conn.commit()
    conn.close()
