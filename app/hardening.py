"""Phase 6: per-flag-instance hardening toggle.

Two independent ways for a given flag instance to be "hardened," checked
in this order by is_hardened():

1. HARDENING_MODE=all (env var, read once at import time) -- forces every
   key hardened, no DB access at all. This is what makes a container
   booted with this env var a standalone, fully-hardened instance: the
   dedicated e2e reference instance from the roadmap, and now also a
   participant-facing "here's the fixed version" reference run
   side-by-side on its own port. Same image, same INSTANCE_HOST-style
   env-var-selected role pattern entrypoint.sh already uses -- no new
   Docker image, no code path that isn't exercised by the normal
   per-instance toggle too.

2. A row in hardening_state with hardened=1 -- the live, per-instance
   toggle a trainer flips at runtime (Phase 7's dashboard writes here;
   nothing does yet, so today this is set by hand via `write_db`-style
   direct SQL, or a test fixture). A flag_key with NO row is implicitly
   vulnerable -- this is what lets /ops/__reset_lab__'s existing
   seed.db-over-app.db file swap reset every toggle back to vulnerable
   for free, with zero reset-specific code for this table (see
   app/schema.sql's comment on hardening_state and app/ops.py).

Every vulnerable route calls is_hardened(KEY) and branches -- see
app/customer.py, app/admin.py, app/auth.py for the first few instances
wired up. The branch must be a genuine fix (parameterized query, output
escaping, a real header, an enforced policy), not just "return an error
instead" -- the whole point of hardening mode is showing participants
what correct looks like, not that the door got locked.
"""
import hashlib
import hmac
import os

from flask import current_app, request

from .db import get_db

# Read once at import time (module-level, not per-request) -- this is a
# container-launch-time role selection, like INSTANCE_HOST, not something
# that changes mid-process.
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
    """Flip one instance's toggle. Upsert, not a plain UPDATE -- a key
    with no row yet is implicitly vulnerable (is_hardened()'s default),
    so the first-ever toggle for a given key has to INSERT, not silently
    no-op against a row that was never created. Intended caller: the
    Phase 7 trainer dashboard (not built yet); also used directly by
    tests/hardening/ to exercise each branch without that dashboard."""
    db = get_db()
    db.execute(
        "INSERT INTO hardening_state (flag_key, hardened) VALUES (?, ?) "
        "ON CONFLICT(flag_key) DO UPDATE SET hardened = excluded.hardened",
        (flag_key, 1 if hardened else 0),
    )
    db.commit()


def all_states() -> dict:
    """flag_key -> bool for every key in the catalog, filling in the
    implicit-False default for keys that have never been toggled. Meant
    for the Phase 7 trainer dashboard to render every switch's current
    state, including ones with no row at all yet."""
    from . import flags as flags_module

    if FORCE_ALL:
        return {key: True for key in flags_module.VALID_KEYS}
    db = get_db()
    rows = db.execute("SELECT flag_key, hardened FROM hardening_state").fetchall()
    state = {key: False for key in flags_module.VALID_KEYS}
    state.update({r["flag_key"]: bool(r["hardened"]) for r in rows})
    return state


def csrf_token() -> str:
    """A standard double-submit-cookie-style anti-CSRF token: derived
    deterministically (HMAC) from the current session cookie plus the
    app's SECRET_KEY, computed fresh on every call rather than stored
    anywhere -- no schema change needed, and it's automatically
    unguessable to anyone who doesn't already have the session cookie
    (which they'd need for the rest of the attack to matter anyway).
    Used by CSRF_TEACH/CSRF_EXERCISE's hardened branches (customer.py)
    and exposed as a Jinja global (see app/__init__.py) so templates can
    embed it in a hidden form field directly."""
    session_token = request.cookies.get("wgs_session", "")
    secret = current_app.config["SECRET_KEY"]
    return hmac.new(secret.encode(), session_token.encode(), hashlib.sha256).hexdigest()
