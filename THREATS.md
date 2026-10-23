# Threat Model — Trust Vault

## Assets
- User credentials and password hashes
- Authentication tokens and signing secret
- Stored documents and file contents
- Document ownership and sharing records
- Audit log records

## Threats and Mitigations
1. Unauthorized access: protected endpoints should require valid authentication.
2. Broken object-level authorization: every document operation must check ownership or active sharing permissions.
3. Credential compromise: passwords are hashed; production deployments must use strong credentials and rate limiting.
4. Token compromise: use HTTPS, short token lifetimes, and secure secret management.
5. Malicious uploads: enforce size limits and validate file handling. Malware scanning is not currently implemented.
6. Path traversal: store files under server-generated internal names and never trust user-supplied paths.
7. Audit-log modification: verify the hash chain. A hash chain alone does not prevent an administrator from rewriting the entire database.
8. Data loss: use protected backups and persistent storage.
9. Information disclosure: avoid exposing private file paths, tokens, secrets, or other users' data in API responses and logs.

## Remaining Production Risks
- Malware scanning and content-type validation require further review.
- Rate limiting and account recovery require review.
- Persistent storage permissions and backups require configuration.
- Authorization and revocation behavior must be tested automatically.
- Production HTTPS, monitoring, and secret management are required.
