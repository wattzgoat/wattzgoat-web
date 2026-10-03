"""Guided mode: an optional left-hand panel of hints for the page a
participant is on.

Whether it is OFFERED is decided per instance, never by a participant:

- A STANDALONE instance (the /participants console is enabled) offers it only
  when started with GUIDED_MODE=true.
- Anywhere else it is offered only while an instructor has switched it on in
  the instructor dashboard. That switch is stored in lab_meta, in the
  database shared with the instructor instance, so it covers every
  participant instance using that data. Resets carry it over.
- Otherwise it is not offered at all: no switch, no panel.

Whether it is ON is each participant's own choice, kept in a cookie in their
own browser (the same way their identity is tracked), so one person turning
it on never affects anyone else sharing the instance.
"""
import hashlib
import sqlite3
from types import SimpleNamespace

from flask import current_app, g, request

from . import flags, hardening
from .db import get_db
from .guidance import BEYOND, BEYOND_ENDPOINTS, FLAG_PAGE, GUIDED_META_KEY, HINTS

COOKIE = "wg_guided"


def setting_enabled() -> bool:
    """The instructor's switch, as stored in the shared database."""
    try:
        row = get_db().execute("SELECT value FROM lab_meta WHERE key = ?", (GUIDED_META_KEY,)).fetchone()
    except sqlite3.Error:
        return False
    return bool(row and row["value"] == "1")


def set_setting(enabled: bool) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO lab_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (GUIDED_META_KEY, "1" if enabled else "0"),
    )
    db.commit()


def offered() -> bool:
    """Is guided mode available on this instance right now?"""
    if current_app.config.get("STANDALONE_PASSWORD"):
        return bool(current_app.config.get("GUIDED_MODE"))
    return setting_enabled()


def state():
    """What the page header needs: is it offered, and is this participant's
    own switch on."""
    available = offered()
    return SimpleNamespace(available=available, on=available and request.cookies.get(COOKIE) == "1")


def _opaque(flag_key: str) -> str:
    """A stable id for a hint card that doesn't spell out which flag it is."""
    return hashlib.sha1(flag_key.encode()).hexdigest()[:8]


def panel():
    """Everything the panel template needs for the current page, or None when
    guided mode is off for this visitor."""
    st = state()
    if not st.on:
        return None

    endpoint = request.endpoint
    if endpoint in BEYOND_ENDPOINTS:
        scope = "beyond"
        keys = [k for k, _c, _n in flags.CATALOG if FLAG_PAGE.get(k) == BEYOND]
    else:
        scope = "page"
        keys = [k for k, _c, _n in flags.CATALOG if endpoint and FLAG_PAGE.get(k) == endpoint]

    result = {"scope": scope, "total": len(keys), "found": 0, "cards": [], "unhinted": 0}
    if not keys:
        return result

    redeemed = {
        row["flag_key"]
        for row in get_db().execute(
            "SELECT flag_key FROM flag_redemptions WHERE participant_id = ?", (g.participant_id,)
        ).fetchall()
    }
    for key in keys:
        if key in redeemed:
            result["found"] += 1          # solved: counted, but its hints are gone
            continue
        if hardening.is_hardened(key):
            result["cards"].append({"id": _opaque(key), "fixed": True, "hints": []})
        elif key in HINTS:
            result["cards"].append({"id": _opaque(key), "fixed": False, "hints": list(HINTS[key])})
        else:
            result["unhinted"] += 1
    return result
