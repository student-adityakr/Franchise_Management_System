"""SQLite database helpers for FranchiseOps AI Milestone 1."""
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "FRANCHISEOPS_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "franchiseops_users.db"),
)


@contextmanager
def db_connection():
    """Open a database connection and commit or roll back safely."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the user table if it does not already exist."""
    with db_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reset_otp_hash TEXT,
                reset_otp_expires_at REAL,
                reset_otp_attempts INTEGER NOT NULL DEFAULT 0,
                reset_otp_last_sent_at REAL
            );
            """
        )


def _as_dict(row):
    return dict(row) if row is not None else None


def get_user_by_id(user_id):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _as_dict(row)


def get_user_by_username(username):
    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
    return _as_dict(row)


def get_user_by_email(email):
    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
            (email.strip(),),
        ).fetchone()
    return _as_dict(row)


def get_user_by_login(username_or_email):
    """Allow login with either the username or email address."""
    value = username_or_email.strip()
    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
            (value, value),
        ).fetchone()
    return _as_dict(row)


def create_user(username, email, password_hash, security_question, security_answer_hash):
    """Insert a new user. Returns (success, reason)."""
    try:
        with db_connection() as conn:
            conn.execute(
                """INSERT INTO users
                   (username, email, password_hash, security_question, security_answer_hash)
                   VALUES (?, ?, ?, ?, ?)""",
                (username.strip(), email.strip().lower(), password_hash,
                 security_question, security_answer_hash),
            )
        return True, "created"
    except sqlite3.IntegrityError as exc:
        # Do not expose internal SQL details to the user.
        message = str(exc).lower()
        if "users.username" in message:
            return False, "username"
        if "users.email" in message:
            return False, "email"
        return False, "duplicate"


def list_users():
    """Return only safe user information for the admin dashboard."""
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT username, email, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def save_otp(email, otp_hash, expires_at, sent_at):
    """Save a hashed OTP and its expiry for a registered email."""
    with db_connection() as conn:
        conn.execute(
            """UPDATE users
               SET reset_otp_hash = ?, reset_otp_expires_at = ?,
                   reset_otp_attempts = 0, reset_otp_last_sent_at = ?
               WHERE email = ? COLLATE NOCASE""",
            (otp_hash, expires_at, sent_at, email.strip()),
        )


def increment_otp_attempts(user_id):
    with db_connection() as conn:
        conn.execute(
            "UPDATE users SET reset_otp_attempts = reset_otp_attempts + 1 WHERE id = ?",
            (user_id,),
        )


def clear_otp(user_id):
    with db_connection() as conn:
        conn.execute(
            """UPDATE users SET reset_otp_hash = NULL, reset_otp_expires_at = NULL,
               reset_otp_attempts = 0 WHERE id = ?""",
            (user_id,),
        )


def update_password(user_id, new_password_hash):
    """Update the password and invalidate any outstanding OTP."""
    with db_connection() as conn:
        conn.execute(
            """UPDATE users SET password_hash = ?, reset_otp_hash = NULL,
               reset_otp_expires_at = NULL, reset_otp_attempts = 0
               WHERE id = ?""",
            (new_password_hash, user_id),
        )
