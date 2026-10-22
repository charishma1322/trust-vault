
import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"

app = FastAPI(title="Trust Vault API")


def connect_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)


def record_audit(actor, action, details):
    with connect_db() as db:
        previous = db.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()

        previous_hash = previous["entry_hash"] if previous else "GENESIS"
        timestamp = datetime.now(timezone.utc).isoformat()
        details_json = json.dumps(details, sort_keys=True)

        payload = json.dumps({
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "details": details_json,
            "previous_hash": previous_hash
        }, sort_keys=True)

        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        db.execute("""
            INSERT INTO audit_log
            (timestamp, actor, action, details, previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp, actor, action, details_json,
            previous_hash, entry_hash
        ))


init_db()


@app.get("/")
def home():
    return {"message": "Trust Vault API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/demo/audit")
def demo_audit():
    record_audit("demo-user", "demo_event", {"message": "Test event recorded"})
    return {"message": "Audit event recorded"}


@app.get("/demo/audit")
def get_demo_audit():
    with connect_db() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]
