import os
import re
import uuid
import hmac
import hashlib
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, g
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config

ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "png", "jpg", "jpeg"}
ROLES = {"admin", "manager", "employee"}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    csrf = CSRFProtect(app)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def init_db():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','manager','employee')),
            department TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            department TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS document_permissions (
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            granted_by INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL,
            PRIMARY KEY(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            actor_name TEXT NOT NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            outcome TEXT NOT NULL,
            reason TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE
        );
        """)
        conn.commit()
        conn.close()

    def audit(action, outcome, reason, document_id=None, actor=None):
        # Hash-linked audit entries make accidental/tampering changes detectable.
        conn = db()
        actor_id = actor["id"] if actor else session.get("user_id")
        actor_name = actor["username"] if actor else (session.get("username") or "anonymous")
        previous = conn.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else "GENESIS"
        occurred = utc_now()
        payload = "|".join([
            str(actor_id or ""), actor_name, action, str(document_id or ""),
            outcome, reason, occurred, previous_hash
        ])
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        conn.execute("""INSERT INTO audit_logs
            (actor_id, actor_name, action, document_id, outcome, reason,
             occurred_at, previous_hash, entry_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
             (actor_id, actor_name, action, document_id, outcome, reason,
              occurred, previous_hash, entry_hash))
        conn.commit()

    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                audit("AUTHENTICATE", "DENIED", "Login required")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def can_access(user, document):
        # Central authorization policy. Always called on the server.
        if not user or not document:
            return False, "Missing user or document"
        if user["role"] == "admin":
            return True, "Admin role grants access"
        if document["owner_id"] == user["id"]:
            return True, "User owns this document"
        if user["role"] == "manager" and user["department"] and document["department"] == user["department"]:
            return True, "Manager may access documents in the same department"
        grant = db().execute(
            "SELECT 1 FROM document_permissions WHERE document_id=? AND user_id=?",
            (document["id"], user["id"])
        ).fetchone()
        if grant:
            return True, "Explicit document permission exists"
        return False, "No ownership, department, admin role, or explicit grant"

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        return redirect(url_for("documents"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session.permanent = True
                audit("LOGIN", "ALLOWED", "Valid credentials", actor=user)
                return redirect(url_for("documents"))
            audit("LOGIN", "DENIED", "Invalid username or password", actor={"id": None, "username": username or "unknown"})
            flash("Invalid username or password.")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit("LOGOUT", "ALLOWED", "User logged out")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/documents", methods=["GET"])
    @login_required
    def documents():
        user = current_user()
        # List only documents this user is authorized to see.
        all_docs = db().execute("SELECT * FROM documents ORDER BY created_at DESC").fetchall()
        visible = [d for d in all_docs if can_access(user, d)[0]]
        return render_template("documents.html", documents=visible, user=user)

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        user = current_user()
        if request.method == "POST":
            if user["role"] not in {"admin", "manager", "employee"}:
                audit("UPLOAD", "DENIED", "Role is not permitted to upload")
                abort(403)
            file = request.files.get("file")
            title = request.form.get("title", "").strip()
            if not file or not file.filename or not title:
                flash("Title and file are required.")
                return render_template("upload.html")
            original = secure_filename(file.filename)
            if "." not in original or original.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
                audit("UPLOAD", "DENIED", "File extension is not allowed")
                flash("Allowed file types: PDF, DOCX, TXT, PNG, JPG.")
                return render_template("upload.html")
            stored = f"{uuid.uuid4().hex}.{original.rsplit('.', 1)[1].lower()}"
            path = Path(app.config["UPLOAD_DIR"]) / stored
            file.save(path)
            cur = db().execute("""INSERT INTO documents
                (title, stored_name, original_name, owner_id, department, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (title, stored, original, user["id"], user["department"], utc_now()))
            doc_id = cur.lastrowid
            db().commit()
            audit("UPLOAD", "ALLOWED", "Uploader becomes document owner", doc_id)
            flash("Document uploaded.")
            return redirect(url_for("documents"))
        return render_template("upload.html")

    @app.get("/documents/<int:doc_id>/download")
    @login_required
    def download(doc_id):
        user = current_user()
        document = db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        allowed, reason = can_access(user, document)
        if not allowed:
            audit("DOWNLOAD", "DENIED", reason, doc_id)
            # Use 404 to avoid disclosing whether an inaccessible document exists.
            abort(404)
        file_path = Path(app.config["UPLOAD_DIR"]) / document["stored_name"]
        if not file_path.is_file():
            audit("DOWNLOAD", "ERROR", "Stored file is missing", doc_id)
            abort(404)
        audit("DOWNLOAD", "ALLOWED", reason, doc_id)
        return send_file(file_path, as_attachment=True, download_name=document["original_name"])

    @app.post("/documents/<int:doc_id>/grant")
    @login_required
    def grant(doc_id):
        user = current_user()
        document = db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not document:
            abort(404)
        # Only owner or admin can grant access; managers cannot delegate.
        if user["role"] != "admin" and document["owner_id"] != user["id"]:
            audit("GRANT_PERMISSION", "DENIED", "Only owner or admin may grant access", doc_id)
            abort(403)
        target_name = request.form.get("username", "").strip()
        target = db().execute("SELECT * FROM users WHERE username=?", (target_name,)).fetchone()
        if not target:
            flash("User not found.")
            return redirect(url_for("documents"))
        db().execute("""INSERT OR IGNORE INTO document_permissions
            (document_id, user_id, granted_by, created_at) VALUES (?, ?, ?, ?)""",
            (doc_id, target["id"], user["id"], utc_now()))
        db().commit()
        audit("GRANT_PERMISSION", "ALLOWED", f"Explicit access granted to {target_name}", doc_id)
        flash("Permission granted.")
        return redirect(url_for("documents"))

    @app.post("/documents/<int:doc_id>/delete")
    @login_required
    def delete_document(doc_id):
        user = current_user()
        document = db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not document:
            abort(404)
        if user["role"] != "admin" and document["owner_id"] != user["id"]:
            audit("DELETE", "DENIED", "Only owner or admin may delete", doc_id)
            abort(403)
        db().execute("DELETE FROM documents WHERE id=?", (doc_id,))
        db().commit()
        path = Path(app.config["UPLOAD_DIR"]) / document["stored_name"]
        if path.exists():
            path.unlink()
        audit("DELETE", "ALLOWED", "Owner or admin deleted document", doc_id)
        flash("Document deleted.")
        return redirect(url_for("documents"))

    @app.get("/audit")
    @login_required
    def audit_view():
        user = current_user()
        if user["role"] != "admin":
            audit("VIEW_AUDIT", "DENIED", "Admin role required")
            abort(403)
        rows = db().execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500").fetchall()
        return render_template("audit.html", rows=rows)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Database initialized.")

    @app.cli.command("create-user")
    def create_user_command():
        import getpass
        username = input("Username: ").strip()
        password = getpass.getpass("Password (min 12 chars): ")
        role = input("Role (admin/manager/employee): ").strip().lower()
        department = input("Department: ").strip()
        if len(password) < 12 or role not in ROLES:
            raise SystemExit("Password must be 12+ characters and role must be valid.")
        try:
            db().execute("""INSERT INTO users(username,password_hash,role,department,created_at)
                VALUES(?,?,?,?,?)""",
                (username, generate_password_hash(password), role, department, utc_now()))
            db().commit()
            print("User created.")
        except sqlite3.IntegrityError:
            raise SystemExit("Username already exists.")

    @app.cli.command("verify-audit")
    def verify_audit_command():
        rows = db().execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            payload = "|".join([
                str(row["actor_id"] or ""), row["actor_name"], row["action"],
                str(row["document_id"] or ""), row["outcome"], row["reason"],
                row["occurred_at"], previous
            ])
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["entry_hash"]):
                raise SystemExit(f"Audit chain INVALID at row {row['id']}")
            previous = row["entry_hash"]
        print(f"Audit chain valid ({len(rows)} entries).")

    init_db()
    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=False)
