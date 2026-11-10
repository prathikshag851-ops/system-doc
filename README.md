# Secure Document Portal (Flask)

A small secure document-management application demonstrating server-side authorization and an auditable access trail.

## Features
- Password hashes (Werkzeug PBKDF2) and server-side Flask sessions.
- Roles: `admin`, `manager`, `employee`.
- Private file storage outside Flask's `static` directory.
- Authorization enforced on every download, grant, and delete request.
- Policy: admin can access all documents; owner can access their own; managers can access documents in their department; explicitly granted users can access a document.
- Inaccessible document downloads return 404 to avoid revealing whether a document exists.
- Audit entries for allowed and denied decisions, with a SHA-256 hash chain and verification command.
- CSRF protection, upload size limit, extension allowlist, randomized storage names.

## Requirements
Python 3.10+

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-secret"  # PowerShell
# export SECRET_KEY="replace-with-a-long-random-secret" # macOS/Linux

flask --app app init-db
flask --app app create-user
flask --app app run
```
Open http://127.0.0.1:5000. Create at least one admin and employee account using `create-user`.
To create a manager, run `flask --app app create-user` and select `manager`; use the same department value to scope access.

## Tests
```bash
pytest -q
```

## Audit integrity
Admin users can view `/audit`. Verify the hash chain:
```bash
flask --app app verify-audit
```
The hash chain makes changes to existing entries detectable, but this demo does not make the database cryptographically immutable against a privileged database administrator. For production, ship logs to a separately controlled append-only/WORM log service.

## Security notes / production hardening
- Use HTTPS and set `COOKIE_SECURE=1`.
- Set a strong random `SECRET_KEY`; never commit secrets.
- Use a production WSGI server (e.g. gunicorn) behind a reverse proxy.
- Add malware scanning and content-based file validation; extension checks alone are not sufficient for hostile uploads.
- Add rate limiting, password reset/MFA, backups, monitoring, and centralized secrets management.
- Use PostgreSQL and object storage with private buckets for multi-instance deployment.
- Configure database/file permissions so the web process has least privilege.
- Review the authorization policy before changing business requirements.

## Authorization decisions
All protected document operations call `can_access(user, document)` in `app.py`. The decision is based on the authenticated server-side user record, not form fields or frontend state. The audit record stores ALLOWED/DENIED plus the reason. Granting is restricted to the document owner or an admin. Deleting is restricted to the owner or an admin.
