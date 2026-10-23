
import os
import sqlite3
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jwt
from pwdlib import PasswordHash
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"
STORAGE_DIR = BASE_DIR / "uploads"
STORAGE_DIR.mkdir(exist_ok=True)

SECRET_KEY = os.environ.get("TRUST_VAULT_SECRET")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("Set TRUST_VAULT_SECRET to a random secret of at least 32 characters.")

ALGORITHM = "HS256"
TOKEN_MINUTES = 30
MAX_FILE_SIZE = 10 * 1024 * 1024

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
        db.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                storage_name TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                shared_with INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY(document_id) REFERENCES documents(id),
                FOREIGN KEY(owner_id) REFERENCES users(id),
                FOREIGN KEY(shared_with) REFERENCES users(id)
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
        """, (timestamp, actor, action, details_json, previous_hash, entry_hash))


def verify_audit_chain():
    with connect_db() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()

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
    username: str = Field(
        min_length=3, max_length=50,
        pattern=r"^[a-zA-Z0-9_.-]+$"
    )
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class ShareRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)


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
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
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


def get_accessible_document(document_id, user_id):
    with connect_db() as db:
        document = db.execute("""
            SELECT d.*, u.username AS owner_username
            FROM documents d
            JOIN users u ON u.id = d.owner_id
            WHERE d.id = ?
            AND (
                d.owner_id = ?
                OR EXISTS (
                    SELECT 1 FROM shares s
                    WHERE s.document_id = d.id
                    AND s.shared_with = ?
                    AND s.revoked_at IS NULL
                )
            )
        """, (document_id, user_id, user_id)).fetchone()
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return dict(document)


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
                (data.username, hashed_password,
                 datetime.now(timezone.utc).isoformat())
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
            "SELECT * FROM users WHERE username = ?", (data.username,)
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


@app.post("/documents/upload", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    original_name = Path(file.filename or "document").name
    if not original_name or original_name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    document_id = str(uuid.uuid4())
    storage_name = secrets.token_hex(24)
    destination = STORAGE_DIR / storage_name
    digest = hashlib.sha256()
    size = 0

    try:
        with destination.open("xb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413, detail="Maximum file size is 10 MB"
                    )
                digest.update(chunk)
                output.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="Empty files are not allowed")

        created_at = datetime.now(timezone.utc).isoformat()
        with connect_db() as db:
            db.execute("""
                INSERT INTO documents
                (id, owner_id, original_name, storage_name, size, sha256, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                document_id, user["id"], original_name, storage_name,
                size, digest.hexdigest(), created_at
            ))
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    record_audit(user["username"], "document_uploaded", {
        "document_id": document_id, "size": size, "sha256": digest.hexdigest()
    })
    return {
        "id": document_id,
        "filename": original_name,
        "size": size,
        "sha256": digest.hexdigest(),
        "created_at": created_at
    }


@app.get("/documents")
def list_documents(user=Depends(get_current_user)):
    with connect_db() as db:
        rows = db.execute("""
            SELECT DISTINCT d.id, d.owner_id, d.original_name, d.size,
                   d.sha256, d.created_at, u.username AS owner,
                   CASE WHEN d.owner_id = ? THEN 'owner' ELSE 'shared' END AS access
            FROM documents d
            JOIN users u ON u.id = d.owner_id
            LEFT JOIN shares s ON s.document_id = d.id
            WHERE d.owner_id = ?
               OR (s.shared_with = ? AND s.revoked_at IS NULL)
            ORDER BY d.created_at DESC
        """, (user["id"], user["id"], user["id"])).fetchall()
    return [dict(row) for row in rows]


@app.get("/documents/{document_id}/download")
def download_document(document_id: str, user=Depends(get_current_user)):
    document = get_accessible_document(document_id, user["id"])
    path = STORAGE_DIR / document["storage_name"]
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Stored file not found")

    record_audit(user["username"], "document_downloaded", {
        "document_id": document_id
    })
    return FileResponse(
        path, filename=document["original_name"],
        media_type="application/octet-stream"
    )


@app.post("/documents/{document_id}/share", status_code=201)
def share_document(
    document_id: str,
    data: ShareRequest,
    user=Depends(get_current_user)
):
    with connect_db() as db:
        document = db.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, user["id"])
        ).fetchone()
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        target = db.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="Recipient not found")
        if target["id"] == user["id"]:
            raise HTTPException(status_code=400, detail="Cannot share with yourself")

        active = db.execute("""
            SELECT id FROM shares
            WHERE document_id = ? AND shared_with = ? AND revoked_at IS NULL
        """, (document_id, target["id"])).fetchone()
        if active:
            raise HTTPException(status_code=409, detail="Document already shared with this user")

        cursor = db.execute("""
            INSERT INTO shares
            (document_id, owner_id, shared_with, created_at, revoked_at)
            VALUES (?, ?, ?, ?, NULL)
        """, (
            document_id, user["id"], target["id"],
            datetime.now(timezone.utc).isoformat()
        ))
        share_id = cursor.lastrowid

    record_audit(user["username"], "document_shared", {
        "document_id": document_id, "recipient": data.username
    })
    return {"share_id": share_id, "message": "Document shared successfully"}


@app.delete("/documents/{document_id}/share/{share_id}")
def revoke_share(
    document_id: str,
    share_id: int,
    user=Depends(get_current_user)
):
    with connect_db() as db:
        share = db.execute("""
            SELECT s.id, u.username AS recipient
            FROM shares s JOIN users u ON u.id = s.shared_with
            WHERE s.id = ? AND s.document_id = ?
              AND s.owner_id = ? AND s.revoked_at IS NULL
        """, (share_id, document_id, user["id"])).fetchone()

        if share is None:
            raise HTTPException(status_code=404, detail="Active share not found")

        db.execute(
            "UPDATE shares SET revoked_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), share_id)
        )

    record_audit(user["username"], "document_share_revoked", {
        "document_id": document_id, "share_id": share_id,
        "recipient": share["recipient"]
    })
    return {"message": "Share revoked successfully"}


@app.get("/documents/{document_id}/shares")
def list_shares(document_id: str, user=Depends(get_current_user)):
    with connect_db() as db:
        document = db.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, user["id"])
        ).fetchone()
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        rows = db.execute("""
            SELECT s.id AS share_id, u.username, s.created_at, s.revoked_at
            FROM shares s JOIN users u ON u.id = s.shared_with
            WHERE s.document_id = ? AND s.owner_id = ?
            ORDER BY s.id DESC
        """, (document_id, user["id"])).fetchall()
    return [dict(row) for row in rows]


@app.get("/audit/verify")
def audit_verification(user=Depends(get_current_user)):
    return verify_audit_chain()
