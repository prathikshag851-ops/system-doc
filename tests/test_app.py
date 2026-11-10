import io
import sqlite3
from werkzeug.security import generate_password_hash
from app import create_app

def setup_app(tmp_path):
    db = str(tmp_path / "test.sqlite")
    uploads = str(tmp_path / "uploads")
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                      "DATABASE": db, "UPLOAD_DIR": uploads,
                      "SECRET_KEY": "test-secret"})
    with app.app_context():
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO users(username,password_hash,role,department,created_at) VALUES(?,?,?,?,?)",
                     ("alice", generate_password_hash("long-test-password"), "employee", "sales", "now"))
        conn.execute("INSERT INTO users(username,password_hash,role,department,created_at) VALUES(?,?,?,?,?)",
                     ("bob", generate_password_hash("long-test-password"), "employee", "engineering", "now"))
        conn.commit()
        conn.close()
    return app

def login(client, username):
    return client.post("/login", data={"username": username, "password": "long-test-password"})

def test_owner_can_upload_and_download_but_other_user_cannot(tmp_path):
    app = setup_app(tmp_path)
    alice = app.test_client()
    login(alice, "alice")
    response = alice.post("/documents/upload", data={
        "title": "Secret", "file": (io.BytesIO(b"private data"), "secret.txt")
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    listing = alice.get("/documents")
    assert b"Secret" in listing.data
    bob = app.test_client()
    login(bob, "bob")
    assert b"Secret" not in bob.get("/documents").data
    assert bob.get("/documents/1/download").status_code == 404

def test_owner_can_grant_access(tmp_path):
    app = setup_app(tmp_path)
    alice = app.test_client()
    login(alice, "alice")
    alice.post("/documents/upload", data={
        "title": "Shared", "file": (io.BytesIO(b"share me"), "shared.txt")
    }, content_type="multipart/form-data")
    alice.post("/documents/1/grant", data={"username": "bob"})
    bob = app.test_client()
    login(bob, "bob")
    assert bob.get("/documents/1/download").status_code == 200
