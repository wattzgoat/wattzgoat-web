"""Next-phase item 1: the trainer role's own auth, completely decoupled
from the participant app's users/sessions tables and its deliberately
weak admin stack.

- Own database (TRAINER_DB_PATH, see app/trainer_schema.sql), separate
  from app.db and never touched by a lab reset.
- Real, salted password hashing (werkzeug.security), not weak_hash().
- Real, unguessable session tokens (secrets.token_hex), not the
  participant app's deliberately sequential issue_session_token().
- Own cookie name (wgt_session) so it can never be confused with, or
  accidentally read as, the participant app's wgs_session.

This module is only ever imported by app/trainer.py, and only matters
when TRAINER_DASHBOARD=true (see app/__init__.py) -- the participant-
facing app never touches trainer_accounts/trainer_sessions at all.
"""
import secrets
import sqlite3
from functools import wraps

from flask import current_app, g, redirect, request, url_for
from werkzeug.security import check_password_hash

TRAINER_COOKIE = "wgt_session"


def get_trainer_db() -> sqlite3.Connection:
    """Separate connection, separate file, separate flask.g slot from
    app/db.py's get_db() -- the two are never the same connection, on
    purpose (see this module's docstring)."""
    if "trainer_db" not in g:
        g.trainer_db = sqlite3.connect(current_app.config["TRAINER_DB_PATH"])
        g.trainer_db.row_factory = sqlite3.Row
        g.trainer_db.execute("PRAGMA journal_mode=WAL")
    return g.trainer_db


def close_trainer_db(e=None) -> None:
    db = g.pop("trainer_db", None)
    if db is not None:
        db.close()


def issue_trainer_session(email: str) -> str:
    db = get_trainer_db()
    token = secrets.token_hex(32)
    db.execute(
        "INSERT INTO trainer_sessions (token, trainer_email) VALUES (?, ?)", (token, email)
    )
    db.commit()
    return token


def authenticate(email: str, password: str) -> bool:
    db = get_trainer_db()
    row = db.execute(
        "SELECT password_hash FROM trainer_accounts WHERE email = ?", (email,)
    ).fetchone()
    # Still run check_password_hash against SOME hash on a miss (a
    # throwaway one, computed fresh) rather than short-circuiting on
    # "no such account" -- a real, if minor, timing-safety habit worth
    # keeping in code that's explicitly meant to be the hardened
    # counter-example to the participant app's own auth.
    if row is None:
        check_password_hash("scrypt:32768:8:1$0" * 8, password)
        return False
    return check_password_hash(row["password_hash"], password)


def current_trainer():
    token = request.cookies.get(TRAINER_COOKIE)
    if not token:
        return None
    db = get_trainer_db()
    return db.execute(
        "SELECT trainer_accounts.*, trainer_sessions.logged_out_at FROM trainer_sessions "
        "JOIN trainer_accounts ON trainer_accounts.email = trainer_sessions.trainer_email "
        "WHERE trainer_sessions.token = ? AND trainer_sessions.logged_out_at IS NULL",
        (token,),
    ).fetchone()


def trainer_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        g.trainer = current_trainer()
        if g.trainer is None:
            return redirect(url_for("trainer.login"))
        return view(*args, **kwargs)

    return wrapped
