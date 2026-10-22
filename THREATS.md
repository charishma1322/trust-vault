**# Trust Vault — Threat Model**



**## 1. Purpose**



**Trust Vault is intended to provide secure document sharing with access control and an auditable record of important actions. The main security goal is to ensure that only authorized users can access shared documents.**



**## 2. Assets to Protect**



**- User accounts and authentication credentials.**

**- Uploaded documents and their contents.**

**- Document ownership and sharing permissions.**

**- Audit records used to investigate activity.**

**- Session information and application configuration.**



**## 3. Potential Attackers**



**- An unauthenticated visitor attempting to access private documents.**

**- An authenticated user attempting to access another user's documents.**

**- A user whose document access has been revoked.**

**- Someone attempting to manipulate or delete audit records.**

**- Someone uploading an unexpected or oversized file.**



**## 4. Threats and Mitigations**



**### Threat 1: Unauthorized Document Access**



**\*\*Scenario:\*\* A user changes a document ID in a request to access another user's private document.**



**\*\*Mitigation:\*\* Check the authenticated user's identity and document permissions on the server for every document access request.**



**\*\*Test plan:\*\* Create two users and verify that one user cannot download the other user's private document.**



**\*\*Status:\*\* Not implemented or verified yet.**



**### Threat 2: Sharing Permission Bypass**



**\*\*Scenario:\*\* A user attempts to download a document after their sharing permission has been revoked.**



**\*\*Mitigation:\*\* Check current permissions on every download rather than relying on an earlier authorization decision.**



**\*\*Test plan:\*\* Share a document, revoke access, and verify that the former recipient can no longer download it.**



**\*\*Status:\*\* Not implemented or verified yet.**



**### Threat 3: Weak Authentication**



**\*\*Scenario:\*\* Someone attempts to impersonate another user or use an invalid session.**



**\*\*Mitigation:\*\* Use established password-hashing and session/token security practices. Never store plaintext passwords.**



**\*\*Test plan:\*\* Verify that unauthenticated requests to protected endpoints are rejected.**



**\*\*Status:\*\* Not implemented or verified yet.**



**### Threat 4: Audit Log Tampering**



**\*\*Scenario:\*\* Someone modifies or deletes audit records to conceal activity.**



**\*\*Mitigation:\*\* Link each audit entry to the previous entry using a cryptographic hash and verify the chain. A hash chain alone does not protect against an attacker who can rewrite the entire database.**



**\*\*Test plan:\*\* Modify an audit entry in a test database and verify that the integrity check detects the change.**



**\*\*Status:\*\* Hash-linked demo entries exist; verification and tamper tests are pending.**



**### Threat 5: Unsafe File Uploads**



**\*\*Scenario:\*\* Someone uploads an unsupported file or a file larger than the application should accept.**



**\*\*Mitigation:\*\* Enforce file-size limits, validate allowed file types, generate safe server-side filenames, and avoid trusting user-supplied paths.**



**\*\*Test plan:\*\* Attempt to upload a disallowed file and an oversized file and verify that both are rejected.**



**\*\*Status:\*\* Upload functionality and validation are pending.**



**### Threat 6: Sensitive Information Exposure**



**\*\*Scenario:\*\* Error responses or logs expose document contents, passwords, tokens, or internal file paths.**



**\*\*Mitigation:\*\* Return generic error messages to clients and avoid logging secrets or document contents.**



**\*\*Test plan:\*\* Trigger expected errors and inspect responses and logs for sensitive information.**



**\*\*Status:\*\* Testing pending.**



**## 5. Security Assumptions and Limitations**



**- The server and its deployment environment are trusted.**

**- Authorization must be enforced by the backend, not only by the user interface.**

**- The current demo is not production-secure.**

**- Hash-linked audit entries are not independently tamper-proof without additional protection.**

**- All mitigations and tests must be verified against the actual implementation before they are marked complete.**



**## 6. Testing Record**



**Record each test with its date, setup, expected result, actual result, and any fix made. Do not mark a security test as passed until it has actually been run.**

