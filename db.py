# db.py
# -----------------------------------------------------------------
# SQLite handling for Beyonder AI — users, chat history, login logs,
# and admin-injected messages. Everything lives in a single file
# (beyonder.db), so no extra database service is required on
# PythonAnywhere's free tier.
#
# v2 changes:
#   - chat_history now has a `source` column ("ai" | "admin") so the
#     admin panel can inject messages directly into a user's live
#     chat, and the frontend can poll for just those.
#   - init_db() is migration-safe: it will add the new column to an
#     existing database instead of requiring a fresh beyonder.db.
#   - Added indexes for the columns that are queried most often.
# -----------------------------------------------------------------

import sqlite3
import time
from flask import g

DB_PATH = "beyonder.db"


def get_db():
    """Keep one connection per request context; closed automatically
    when the request ends (see close_db)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def init_db():
    """Creates tables on first run, and migrates older databases
    (adds any column/index introduced in later versions) so existing
    data is never lost or requires a manual reset."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            email           TEXT NOT NULL UNIQUE,
            password_hash   TEXT NOT NULL,
            created_at      REAL NOT NULL,
            last_login_at   REAL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email      TEXT NOT NULL,
            user_message    TEXT NOT NULL,
            ai_response     TEXT NOT NULL,
            timestamp       REAL NOT NULL,
            source          TEXT NOT NULL DEFAULT 'ai'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email      TEXT NOT NULL,
            ip_address      TEXT,
            timestamp       REAL NOT NULL,
            success         INTEGER NOT NULL DEFAULT 1
        )
    """)

    # ---- Migration: add `source` column if this is an older DB ----
    if not _column_exists(cur, "chat_history", "source"):
        cur.execute("ALTER TABLE chat_history ADD COLUMN source TEXT NOT NULL DEFAULT 'ai'")

    # ---- Indexes (safe to run every startup) ----
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_user_email ON chat_history(user_email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_source ON chat_history(user_email, source, id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_email ON login_logs(user_email)")

    conn.commit()
    conn.close()


# ---------------------- USER HELPERS ----------------------

def create_user(name, email, password_hash):
    db = get_db()
    now = time.time()
    db.execute(
        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (name, email, password_hash, now),
    )
    db.commit()


def get_user_by_email(email):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def update_last_login(email):
    db = get_db()
    db.execute("UPDATE users SET last_login_at = ? WHERE email = ?", (time.time(), email))
    db.commit()


def update_password(email, password_hash):
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE email = ?", (password_hash, email))
    db.commit()


def get_all_users():
    db = get_db()
    return db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()


def delete_user(email):
    db = get_db()
    db.execute("DELETE FROM users WHERE email = ?", (email,))
    db.execute("DELETE FROM chat_history WHERE user_email = ?", (email,))
    db.execute("DELETE FROM login_logs WHERE user_email = ?", (email,))
    db.commit()


# ---------------------- CHAT HELPERS ----------------------

def save_chat(user_email, user_message, ai_response, source="ai"):
    """source is 'ai' for normal assistant replies logged from the
    frontend, or 'admin' for messages an admin injects manually."""
    db = get_db()
    cur = db.execute(
        "INSERT INTO chat_history (user_email, user_message, ai_response, timestamp, source) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_email, user_message, ai_response, time.time(), source),
    )
    db.commit()
    return cur.lastrowid


def save_admin_message(user_email, message):
    """Injects a message from the admin panel into a user's chat
    history. The frontend polls for these separately via
    get_new_admin_messages() and renders them as an incoming message."""
    return save_chat(user_email, "", message, source="admin")


def get_all_chats(limit=500):
    db = get_db()
    return db.execute(
        "SELECT * FROM chat_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()


def get_chats_for_user(email, limit=500):
    db = get_db()
    return db.execute(
        "SELECT * FROM chat_history WHERE user_email = ? ORDER BY timestamp ASC LIMIT ?",
        (email, limit),
    ).fetchall()


def get_new_admin_messages(user_email, since_id=0):
    """Used by GET /api/check-messages — returns admin-authored
    messages newer than `since_id` for this user only."""
    db = get_db()
    return db.execute(
        "SELECT id, ai_response, timestamp FROM chat_history "
        "WHERE user_email = ? AND source = 'admin' AND id > ? "
        "ORDER BY id ASC",
        (user_email, since_id),
    ).fetchall()


# ---------------------- LOGIN LOG HELPERS ----------------------

def log_login_attempt(email, ip_address, success=True):
    db = get_db()
    db.execute(
        "INSERT INTO login_logs (user_email, ip_address, timestamp, success) VALUES (?, ?, ?, ?)",
        (email, ip_address, time.time(), 1 if success else 0),
    )
    db.commit()


def get_all_login_logs(limit=500):
    db = get_db()
    return db.execute(
        "SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
