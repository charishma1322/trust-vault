**# PROMPTS.md — Trust Vault**



**## Entry 1 — 22 October 2026**



**\*\*Task:\*\* Set up the initial Trust Vault backend.**



**\*\*What I asked AI:\*\* Help me create a beginner-friendly FastAPI backend with a SQLite database and an audit log.**



**\*\*What AI produced:\*\* A FastAPI application with a health endpoint, demo audit endpoints, and a hash-linked audit log stored in SQLite.**



**\*\*What I tested:\*\* Started the local server and tested the health endpoint and demo audit endpoint using the interactive API documentation.**



**\*\*What still needs improvement:\*\* The demo endpoints do not have authentication or authorization. The audit log needs integrity verification and automated tests.**



**\*\*My changes:\*\* I created the project folders and files, ran the application locally, and checked the endpoint responses. I will document additional changes and their Git commit references as I make them.**



**\*\*Related commit:\*\* Pending — add the commit reference after committing this work.**





**## Entry 2 — 23 October 2026**



**\*\*Task:\*\* Add audit-chain integrity verification.**



**\*\*What I asked AI:\*\* Help me extend the Trust Vault audit log with a function that verifies the hash chain and detects modified or inconsistent audit entries.**



**\*\*What AI produced:\*\* A Python verification function that checks each audit entry's previous hash and recalculates its SHA-256 hash, plus a FastAPI endpoint at `/demo/audit/verify`.**



**\*\*What was wrong or needed attention:\*\* The verification logic needed to use the same data format as the audit-entry creation logic so that valid entries could be verified correctly.**



**\*\*What I changed:\*\* I added the verification function and API endpoint to `main.py`. I need to test both a valid audit chain and a deliberately modified test entry to confirm that tampering is detected.**



**\*\*Test result:\*\* \[Replace this with the actual result you observed. Do not claim tampering detection passed until you test it.]**



**\*\*Related commit:\*\* \[Add the Git commit ID after committing this change.]**

