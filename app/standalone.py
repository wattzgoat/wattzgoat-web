"""Hidden /participants console for STANDALONE (trainer-less) instances.

A participant-facing instance that is not paired with an instructor
container has no other way to reset itself or see class progress, so this
blueprint puts the same tools inside the app itself: the participant
leaderboard (with a per-participant redeemed-flags view) plus Reset Lab,
Reset App, Reset All Redemptions and a per-participant Reset Redemption.

It is only registered when STANDALONE=true (see app/__init__.py). Unset or
false -- which is what a trainer-paired instance should use -- means the
routes don't exist at all (plain 404). It is deliberately not linked from
anywhere and not listed in robots.txt, but it is reachable on the same
ports as the rest of the app by anyone who guesses the path, so it sits
behind a password (STANDALONE_PASSWORD). Without that variable the console
stays disabled.

Because it runs inside the participant process, resets here can also clear
the in-memory rate-limit counters and pending assistant confirmations,
which the separate instructor container cannot reach.
"""
import hmac
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from functools import wraps

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, url_for

from . import assistant, auth, export, personalize, resets
from .db import get_db
from .flags import CATALOG

bp = Blueprint("standalone", __name__, url_prefix="/participants")

COOKIE = "wgp_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW_SECONDS = 5 * 60

# In memory only: a restart logs the instructor out, which is fine.
_sessions: dict[str, float] = {}
_failed_logins: dict[str, list[float]] = defaultdict(list)


def _authed() -> bool:
    token = request.cookies.get(COOKIE)
    expires = _sessions.get(token) if token else None
    if expires is None:
        return False
    if expires < time.time():
        _sessions.pop(token, None)
        return False
    return True


def console_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _authed():
            if request.path.startswith("/participants/api/"):
                return jsonify({"error": "not signed in"}), 401
            return redirect(url_for("standalone.console"))
        return view(*args, **kwargs)

    return wrapped


@bp.context_processor
def _inject_notice():
    return {"notice": resets.notice_from_args(request.args)}


def _clear_in_memory_state() -> None:
    """The counters behind the rate-limiting flags and the assistant's
    pending confirmations live in this process's memory; clear them so a
    reset isn't followed by a lockout or a stale confirmation."""
    auth._login_attempts.clear()
    auth._reset_attempts.clear()
    auth._forged_reset_pending.clear()
    assistant._pending_admin_actions.clear()


def _back(**params):
    return redirect(url_for("standalone.console", **params), 303)


@bp.route("/", strict_slashes=False, methods=["GET"])
def console():
    if not _authed():
        return render_template("standalone_login.html", error=None)
    return render_template(
        "standalone_participants.html",
        total_flags=len(CATALOG),
        standings_url=url_for("standalone.api_leaderboard"),
        reset_participant_url=url_for("standalone.reset_participant_redemption"),
        checklist_url=url_for("standalone.api_participant_checklist"),
        export_summary_url=url_for("standalone.export_summary"),
        export_detail_url=url_for("standalone.export_detail"),
    )


@bp.route("/login", methods=["POST"])
def login():
    now = time.time()
    ip = request.remote_addr or "?"
    recent = [t for t in _failed_logins[ip] if now - t < LOCKOUT_WINDOW_SECONDS]
    _failed_logins[ip] = recent
    if len(recent) >= MAX_FAILED_LOGINS:
        return render_template("standalone_login.html", error="Too many attempts. Try again in a few minutes."), 429

    supplied = request.form.get("password") or ""
    expected = current_app.config.get("STANDALONE_PASSWORD") or ""
    if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
        _failed_logins[ip].append(now)
        return render_template("standalone_login.html", error="Incorrect password."), 401

    _failed_logins.pop(ip, None)
    token = secrets.token_hex(32)
    _sessions[token] = now + SESSION_TTL_SECONDS
    resp = redirect(url_for("standalone.console"), 303)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="Strict", secure=request.is_secure,
                    max_age=SESSION_TTL_SECONDS)
    return resp


@bp.route("/logout", methods=["POST"])
def logout():
    _sessions.pop(request.cookies.get(COOKIE) or "", None)
    resp = redirect(url_for("standalone.console"), 303)
    resp.delete_cookie(COOKIE)
    return resp


@bp.route("/api/leaderboard", methods=["GET"])
@console_required
def api_leaderboard():
    return jsonify({"standings": personalize.participant_standings(), "total_flags": len(CATALOG)})


@bp.route("/export/summary.csv", methods=["GET"])
@console_required
def export_summary():
    return export.summary_response()


@bp.route("/export/detail.csv", methods=["GET"])
@console_required
def export_detail():
    return export.detail_response()


@bp.route("/api/participant_checklist", methods=["GET"])
@console_required
def api_participant_checklist():
    """Backs the leaderboard's "View" popup, same as the instructor
    dashboard's endpoint of the same name (app/trainer.py): one
    participant's full checklist (category/name/done) in CATALOG order,
    matching the participant-facing /progress page. Redemption status
    only, never a flag's actual value."""
    participant_id = request.args.get("participant_id", "")
    if not participant_id:
        abort(400, "participant_id required")
    db = get_db()
    redeemed = {
        row["flag_key"]
        for row in db.execute(
            "SELECT flag_key FROM flag_redemptions WHERE participant_id = ?", (participant_id,)
        ).fetchall()
    }
    checklist = [{"category": category, "name": name, "done": key in redeemed} for key, category, name in CATALOG]
    return jsonify({
        "participant_id": participant_id,
        "checklist": checklist,
        "done_count": len(redeemed),
        "total_count": len(CATALOG),
    })


@bp.route("/reset_lab", methods=["POST"])
@console_required
def reset_lab():
    try:
        resets.reset_lab_state(current_app.config["DB_PATH"], os.environ.get("SEED_DB_PATH", "/app/data/seed.db"))
    except Exception:
        current_app.logger.exception("Reset Lab failed")
        return _back(notice="lab_reset_failed")
    _clear_in_memory_state()
    return _back(notice="lab_reset")


@bp.route("/reset_app", methods=["POST"])
@console_required
def reset_app():
    try:
        resets.reset_app_state(current_app.config["DB_PATH"], os.environ.get("SEED_DB_PATH", "/app/data/seed.db"))
    except Exception:
        current_app.logger.exception("Reset App failed")
        return _back(notice="app_reset_failed")
    _clear_in_memory_state()
    try:
        resets.clear_firmware_files()
    except Exception:
        current_app.logger.exception("Reset App: removing uploaded firmware files failed")
        return _back(notice="app_reset_files_failed")
    return _back(notice="app_reset")


@bp.route("/reset_redemptions", methods=["POST"])
@console_required
def reset_all_redemptions():
    try:
        db = get_db()
        removed = db.execute("DELETE FROM flag_redemptions").rowcount
        db.commit()
    except sqlite3.Error:
        current_app.logger.exception("Reset all redemptions failed")
        return _back(notice="redemptions_reset_all_failed")
    return _back(notice="redemptions_reset_all", n=removed)


@bp.route("/reset_redemption", methods=["POST"])
@console_required
def reset_participant_redemption():
    participant_id = (request.form.get("participant_id") or "").strip()
    if not participant_id:
        return _back(notice="redemptions_reset_no_id")
    try:
        db = get_db()
        removed = db.execute("DELETE FROM flag_redemptions WHERE participant_id = ?", (participant_id,)).rowcount
        db.commit()
    except sqlite3.Error:
        current_app.logger.exception("Reset redemption failed")
        return _back(notice="redemptions_reset_failed")
    return _back(notice="redemptions_reset", n=removed, pid=participant_id[:8])
