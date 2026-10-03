"""Per-flag hardening toggles: each vulnerability can be switched between vulnerable and fixed."""
import hashlib
import hmac
import os

from flask import current_app, request

from .db import get_db

FORCE_ALL = os.environ.get("HARDENING_MODE", "").strip().lower() == "all"


def is_hardened(flag_key: str) -> bool:
    if FORCE_ALL:
        return True
    db = get_db()
    row = db.execute(
        "SELECT hardened FROM hardening_state WHERE flag_key = ?", (flag_key,)
    ).fetchone()
    return bool(row and row["hardened"])


def set_hardened(flag_key: str, hardened: bool) -> None:
    """Switch one flag between vulnerable and fixed."""
    db = get_db()
    db.execute(
        "INSERT INTO hardening_state (flag_key, hardened) VALUES (?, ?) "
        "ON CONFLICT(flag_key) DO UPDATE SET hardened = excluded.hardened",
        (flag_key, 1 if hardened else 0),
    )
    db.commit()


def all_states() -> dict:
    """flag_key -> hardened (bool) for every flag."""
    from . import flags as flags_module

    if FORCE_ALL:
        return {key: True for key in flags_module.VALID_KEYS}
    db = get_db()
    rows = db.execute("SELECT flag_key, hardened FROM hardening_state").fetchall()
    state = {key: False for key in flags_module.VALID_KEYS}
    state.update({r["flag_key"]: bool(r["hardened"]) for r in rows})
    return state


def csrf_token() -> str:
    """Anti-CSRF token derived from the session cookie and the app secret."""
    session_token = request.cookies.get("wgs_session", "")
    secret = current_app.config["SECRET_KEY"]
    return hmac.new(secret.encode(), session_token.encode(), hashlib.sha256).hexdigest()
