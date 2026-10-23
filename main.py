
import os
import sqlite3
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jwt
from pwdlib import PasswordHash
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"
SECRET_KEY = os.environ.get("TRUST_VAULT_SECRET")

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Set TRUST_VAULT_SECRET to a random secret of at least 32 characters."
    )

ALGORITHM = "HS256"
TOKEN_MINUTES = 30

app = FastAPI(title="Trust Vault API")
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)


def connect_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
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


def verify_audit_chain():
    with connect_db() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY id"
        ).fetchall()

    previous_hash = "GENESIS"

    for row in rows:
        if row["previous_hash"] != previous_hash:
            return {
                "valid": False,
                "entry_id": row["id"],
                "reason": "Previous hash mismatch"
            }

        payload = json.dumps({
            "timestamp": row["timestamp"],
            "actor": row["actor"],
            "action": row["action"],
            "details": row["details"],
            "previous_hash": previous_hash
        }, sort_keys=True)

        expected_hash = hashlib.sha256(payload.encode()).hexdigest()

        if not hmac.compare_digest(row["entry_hash"], expected_hash):
            return {
                "valid": False,
                "entry_id": row["id"],
                "reason": "Entry hash mismatch"
            }

        previous_hash = row["entry_hash"]

    return {"valid": True, "entries_checked": len(rows)}


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


def create_token(user_id, username):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
        "jti": secrets.token_urlsafe(16)
    }, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer)
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    with connect_db() as db:
        user = db.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")

    return dict(user)


init_db()


@app.get("/")
def home():
    return {"message": "Trust Vault API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest):
    hashed_password = password_hash.hash(data.password)

    try:
        with connect_db() as db:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (
                    data.username,
                    hashed_password,
                    datetime.now(timezone.utc).isoformat()
                )
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")

    record_audit(data.username, "register", {"user_id": user_id})
    return {"message": "Account created successfully"}


@app.post("/auth/login")
def login(data: LoginRequest):
    with connect_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()

    if user is None or not password_hash.verify(
        data.password, user["password_hash"]
    ):
        record_audit(data.username, "login_failed", {})
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user["id"], user["username"])
    record_audit(data.username, "login_success", {})

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_MINUTES * 60
    }


@app.get("/auth/me")
def my_account(user=Depends(get_current_user)):
    return user


@app.get("/audit/verify")
def audit_verification(user=Depends(get_current_user)):
    return verify_audit_chain()
