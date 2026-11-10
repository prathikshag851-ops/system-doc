import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
    DATABASE = os.environ.get("DATABASE_PATH", str(BASE_DIR / "instance" / "portal.sqlite3"))
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", str(BASE_DIR / "private_uploads"))
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 1800
