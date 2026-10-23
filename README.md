# Trust Vault

Trust Vault is a FastAPI-based document storage API featuring user authentication, private document storage, document sharing, access revocation, and a hash-linked audit log.

## Features

- User registration and login
- JWT bearer-token authentication
- Password hashing
- Authenticated document upload and download
- Document ownership and access checks
- Sharing documents with registered users
- Revoking document shares
- SHA-256 file integrity hashes
- Hash-linked audit logging and audit-chain verification

## Technology Stack

- Python
- FastAPI
- SQLite
- PyJWT
- pwdlib
- Uvicorn

## Run Locally

Install dependencies:

    python -m pip install fastapi "uvicorn[standard]" pyjwt "pwdlib[argon2]" python-multipart

Set a development secret in PowerShell:

    $env:TRUST_VAULT_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(32))")

Start the server:

    python -m uvicorn main:app --reload

Open the interactive API documentation:

    http://127.0.0.1:8000/docs

## Security Notes

Use a persistent, securely managed secret in production. Do not commit secrets, database files, or uploaded documents. Production deployment requires HTTPS, persistent private storage, appropriate backups, and additional security testing.

The audit hash chain can reveal modifications when verified, but a database administrator who can rewrite the entire chain may be able to forge it.

## Testing

Test registration, authentication, uploads, ownership enforcement, sharing, revocation, and audit-chain verification before deployment. Document only test results that have actually been observed.
