"""Authentication and session management for LANWatch Sentinel."""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple

from lanscanner.core.storage import DB_PATH, get_app_config, set_app_config

# Brute-force protection: IP -> list of timestamps
_FAILED_LOGINS: Dict[str, list] = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 120,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000
    )
    return f"{salt}${key.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Safely verify a password against stored salt$hash."""
    try:
        salt, key_hex = stored_hash.split("$", 1)
        test_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120_000
        )
        return hmac.compare_digest(test_key.hex(), key_hex)
    except Exception:
        return False


def init_auth_tables(db_path: Path = DB_PATH):
    """Ensure sessions and auth config tables exist."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

    # Check environment variable auto-configuration
    env_pass = os.environ.get("LANWATCH_ADMIN_PASSWORD") or os.environ.get("AUTH_PASSWORD")
    if env_pass:
        env_user = os.environ.get("LANWATCH_ADMIN_USER", "admin")
        set_admin_credentials(env_user, env_pass)


def is_auth_enabled() -> bool:
    """Return True if authentication is enabled."""
    val = get_app_config("auth_enabled", "1")
    return val == "1"


def is_auth_configured() -> bool:
    """Check if an administrator account has already been initialized."""
    stored_hash = get_app_config("auth_password_hash")
    return bool(stored_hash)


def get_admin_username() -> str:
    """Return the configured administrator username."""
    return get_app_config("auth_username", "admin") or "admin"


def set_admin_credentials(username: str, password: str, db_path: Path = DB_PATH):
    """Set or update the administrator credentials."""
    init_auth_tables(db_path)
    pwd_hash = _hash_password(password)
    set_app_config("auth_username", username.strip() or "admin", db_path)
    set_app_config("auth_password_hash", pwd_hash, db_path)
    set_app_config("auth_enabled", "1", db_path)


def check_rate_limit(client_ip: str) -> Tuple[bool, int]:
    """Check if client IP is rate-limited. Returns (is_locked, remaining_seconds)."""
    now = time.time()
    attempts = [t for t in _FAILED_LOGINS[client_ip] if now - t < LOCKOUT_SECONDS]
    _FAILED_LOGINS[client_ip] = attempts
    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        oldest = attempts[0]
        remaining = int(LOCKOUT_SECONDS - (now - oldest))
        return True, max(1, remaining)
    return False, 0


def record_failed_attempt(client_ip: str):
    """Record a failed login attempt for rate limiting."""
    _FAILED_LOGINS[client_ip].append(time.time())


def clear_rate_limit(client_ip: str):
    """Reset failed attempts on successful login."""
    _FAILED_LOGINS.pop(client_ip, None)


def authenticate(username: str, password: str, client_ip: str = "127.0.0.1") -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Authenticate username and password.
    Returns (success, session_token_or_error_message, username).
    """
    is_locked, remaining = check_rate_limit(client_ip)
    if is_locked:
        return False, f"Troppi tentativi falliti. Riprova tra {remaining} secondi.", None

    admin_user = get_admin_username()
    stored_hash = get_app_config("auth_password_hash")

    if not stored_hash:
        return False, "Autenticazione non ancora configurata.", None

    if username.strip().lower() != admin_user.lower() or not _verify_password(password, stored_hash):
        record_failed_attempt(client_ip)
        return False, "Credenziali non valide. Nome utente o password errati.", None

    clear_rate_limit(client_ip)
    return True, None, admin_user


def create_session(username: str, remember_me: bool = False, db_path: Path = DB_PATH) -> str:
    """Create a new session token stored in SQLite."""
    init_auth_tables(db_path)
    token = secrets.token_urlsafe(32)
    created_at = datetime.utcnow()
    days = 30 if remember_me else 1
    expires_at = created_at + timedelta(days=days)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Cleanup expired sessions
    cur.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
    cur.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, username, created_at.isoformat(), expires_at.isoformat())
    )
    conn.commit()
    conn.close()
    return token


def validate_session(token: Optional[str], db_path: Path = DB_PATH) -> Optional[str]:
    """Validate a session token. Returns username if valid, None if expired or invalid."""
    if not token:
        return None

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?",
            (token,)
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return None

        username, expires_str = row
        expires_at = datetime.fromisoformat(expires_str)
        if datetime.utcnow() > expires_at:
            revoke_session(token, db_path)
            return None

        return username
    except Exception:
        return None


def revoke_session(token: str, db_path: Path = DB_PATH):
    """Revoke a session token upon logout."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass
