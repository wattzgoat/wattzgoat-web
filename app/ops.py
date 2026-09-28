import os

from flask import Blueprint, abort, current_app, jsonify, redirect, request, url_for

from . import assistant, auth, flags, hardening
from .resets import reset_lab_state

bp = Blueprint("ops", __name__, url_prefix="/ops")

# Wired into the admin nav ("Reset Lab" button in base.html) and
# deliberately not gated behind a token beyond ordinary admin login --
# this route only affects the single isolated instance it's running in,
# so there's no additional security boundary to protect beyond that.
#
# What matters is that it works without a container restart: copy the
# pristine seed.db back over the live app.db, and drop any WAL/SHM files
# so a connection doesn't read stale journal data against the
# freshly-copied file. The session-token counter is intentionally left
# alone (it just resumes where it was); the rate-limit counters are
# cleared below.
#
# The copy itself is done via write-to-temp-then-os.replace() rather than
# copying directly over db_path in place. shutil.copyfile() onto a live
# path truncates and streams into the destination file over time, which
# leaves a real window where a concurrent connection (this app is never
# fully idle -- the meter simulator threads hit the DB on their own every
# 20-40s regardless of what else is happening) can open a half-written or
# momentarily empty file and see a schema-less database ("no such table:
# meters"). os.replace() is a single filesystem-level rename, not a
# content copy, so there's no intermediate state for a concurrent
# connection to ever observe -- it's always either the complete old file
# or the complete new one.
@bp.route("/__reset_lab__", methods=["POST"])
def reset_lab():
    db_path = current_app.config["DB_PATH"]
    seed_path = os.environ.get("SEED_DB_PATH", "/app/data/seed.db")

    try:
        reset_lab_state(db_path, seed_path)
    except FileNotFoundError:
        abort(500, "no seed.db to reset from")

    # The attempt counters behind the rate-limiting flags live in memory, so
    # they have to be cleared by hand -- otherwise the very next failed
    # login after a reset would already count as attempt #6.
    auth._login_attempts.clear()
    auth._reset_attempts.clear()
    assistant._pending_admin_actions.clear()

    # Browsers (the admin nav button) land back on the login page, since the
    # reset also wipes every session; curl/scripts still get JSON.
    if request.accept_mimetypes.best_match(["application/json", "text/html"]) == "text/html":
        resp = redirect(url_for("auth.login", reset=1))
        resp.delete_cookie("wgs_session")
        return resp
    return jsonify({"status": "reset"})


# Phase 6: the toggle mechanism this app.db-level endpoint drives is
# app/hardening.py; this route is the ONLY way to flip a toggle until
# Phase 7's trainer dashboard exists (nothing else writes to
# hardening_state yet). Same trust boundary as reset_lab above -- ordinary
# admin login, no extra token -- for the same reason: this only ever
# affects the single isolated instance it's running in. Also what the e2e
# test suite (tests/hardening/) uses to exercise each hardened branch
# against a real running instance, since tests talk HTTP to the app, not
# the DB file directly.
@bp.route("/__set_hardening__", methods=["POST"])
@auth.login_required(role="admin")
def set_hardening():
    flag_key = request.form.get("flag_key") or (request.get_json(silent=True) or {}).get("flag_key")
    hardened_raw = request.form.get("hardened")
    if hardened_raw is None:
        hardened_raw = (request.get_json(silent=True) or {}).get("hardened")

    if flag_key not in flags.VALID_KEYS:
        abort(400, f"unknown flag_key: {flag_key!r}")

    hardened = str(hardened_raw).strip().lower() in ("1", "true", "yes", "on")
    hardening.set_hardened(flag_key, hardened)
    return jsonify({"flag_key": flag_key, "hardened": hardened})


# Read-only companion to the above -- lets the trainer dashboard (Phase 7)
# and tests confirm current state without guessing from side effects.
@bp.route("/__hardening_status__", methods=["GET"])
@auth.login_required(role="admin")
def hardening_status():
    return jsonify(hardening.all_states())
