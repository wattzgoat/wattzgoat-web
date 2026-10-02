"""Trainer dashboard -- a live-class tool for toggling hardening state,
resetting the lab, and watching participant progress, now running as
its OWN decoupled role (next-phase item 1), not an admin-gated page
inside the participant app.

TRAINER_DASHBOARD=true (see app/__init__.py) makes a container boot as
this role INSTEAD OF the participant-facing app -- same image, same
boot-time role-selection pattern entrypoint.sh already uses for
HARDENING_MODE=all. Only this blueprint is registered on that process;
there is no auth/customer/admin surface here at all.

Two databases, two purposes:
- current_app.config["DB_PATH"] (app/db.py:get_db()) -- the SAME app.db
  the target participant instance uses (shared volume). Hardening
  state, flag redemptions, participant nicknames, and the reset-lab
  file-swap all read/write here, exactly as they did when this was an
  in-process blueprint.
- current_app.config["TRAINER_DB_PATH"] (app/trainer_auth.py) -- the
  trainer role's OWN accounts/sessions, entirely separate, never
  touched by a reset.

Known, accepted limitation of the decoupling (not fixed here, not an
oversight): ops.py's original reset_lab() also cleared a few in-memory
dicts living inside the PARTICIPANT process (auth._login_attempts,
auth._reset_attempts, assistant._pending_admin_actions) -- rate-limit
counters and pending AI-assistant confirmations. Now that the trainer
runs as a separate process, it has no way to reach into that other
process's memory to clear them; reset_lab() below can only reset what
actually lives in the shared DB. In practice this means a lab reset no
longer clears an in-progress rate-limit lockout or a pending assistant
confirmation on the participant side until that process's own counters
age out or it restarts -- a real, minor regression from the in-process
version, traded for genuine auth decoupling. Revisit if/when the parked
multi-instance-sync work (Design Reference S10.1) picks up a
trainer-to-participant command channel for other reasons anyway; not
worth building a one-off endpoint just for this alone.
"""
import os
import sqlite3

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from .db import get_db
from .flags import CATALOG
from . import hardening
from . import personalize
from . import resets
from . import trainer_auth
from .trainer_auth import trainer_login_required

bp = Blueprint("trainer", __name__, url_prefix="/instructor")


def _catalog_grouped():
    """CATALOG (key, category, name) tuples grouped by category, in
    catalog order -- the same grouping the instructor guide and
    progress.py use, so the dashboard's layout matches what a trainer
    already recognizes from the walkthrough."""
    grouped = {}
    for key, category, name in CATALOG:
        grouped.setdefault(category, []).append({"key": key, "name": name})
    return grouped


def _keys_in_category(category: str) -> list[str]:
    return [key for key, cat, _ in CATALOG if cat == category]


_NEXT_ENDPOINTS = {"dashboard": "trainer.dashboard", "leaderboard": "trainer.leaderboard"}


def _back_to(next_name: str, **params):
    endpoint = _NEXT_ENDPOINTS.get(next_name, "trainer.dashboard")
    return redirect(url_for(endpoint, **params), 303)


@bp.context_processor
def _inject_notice():
    return {"notice": resets.notice_from_args(request.args)}


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("trainer_login.html")

    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    if not trainer_auth.authenticate(email, password):
        return render_template("trainer_login.html", error="Invalid email or password."), 401

    token = trainer_auth.issue_trainer_session(email)
    resp = redirect(url_for("trainer.dashboard"))
    resp.set_cookie(trainer_auth.TRAINER_COOKIE, token, httponly=True, secure=True, samesite="Strict")
    return resp


@bp.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get(trainer_auth.TRAINER_COOKIE)
    if token:
        db = trainer_auth.get_trainer_db()
        db.execute(
            "UPDATE trainer_sessions SET logged_out_at = datetime('now') WHERE token = ?", (token,)
        )
        db.commit()
    resp = redirect(url_for("trainer.login"))
    resp.delete_cookie(trainer_auth.TRAINER_COOKIE)
    return resp


@bp.route("/", methods=["GET"])
@trainer_login_required
def dashboard():
    # See app/hardening.py -- FORCE_ALL is read from THIS process's own
    # HARDENING_MODE env var. A trainer container has no ordinary reason
    # to set that on itself, but the check is kept for the same defensive
    # reason the original v1 blueprint had it: better a clean 404 than a
    # toggle page whose switches are all inert.
    if hardening.FORCE_ALL:
        abort(404)
    return render_template(
        "trainer_dashboard.html",
        grouped_catalog=_catalog_grouped(),
        categories=list(_catalog_grouped().keys()),
        total_flags=len(CATALOG),
        trainer_name=g.trainer["name"],
        participant_base_url=current_app.config.get("PARTICIPANT_BASE_URL", ""),
    )


@bp.route("/api/summary", methods=["GET"])
@trainer_login_required
def api_summary():
    """Polled by the dashboard's JS every few seconds -- hardening
    state, redemption progress, and the participant roster, all in one
    call rather than three separate ones, to keep polling cheap."""
    if hardening.FORCE_ALL:
        abort(404)

    db = get_db()

    hardening_state = hardening.all_states()

    redemption_rows = db.execute(
        "SELECT flag_key, COUNT(DISTINCT participant_id) AS count FROM flag_redemptions GROUP BY flag_key"
    ).fetchall()
    redemption_counts = {row["flag_key"]: row["count"] for row in redemption_rows}

    participant_rows = db.execute(
        "SELECT participant_id, MAX(redeemed_by) AS redeemed_by, COUNT(*) AS flags_redeemed, "
        "MAX(redeemed_at) AS last_activity "
        "FROM flag_redemptions GROUP BY participant_id ORDER BY flags_redeemed DESC, last_activity DESC"
    ).fetchall()
    participants = [
        {
            "participant_id": row["participant_id"],
            "redeemed_by": row["redeemed_by"],
            "flags_redeemed": row["flags_redeemed"],
            "last_activity": row["last_activity"],
        }
        for row in participant_rows
    ]

    total_redemptions = db.execute("SELECT COUNT(*) AS c FROM flag_redemptions").fetchone()["c"]

    # Next-phase item 2: category-level state -- "on" only when every
    # flag in that category is currently hardened, so the dashboard's
    # per-category switch reflects true/mixed/false accurately rather
    # than guessing from just the first flag in the group.
    category_state = {
        category: all(hardening_state.get(key, False) for key in keys)
        for category, keys in ((c, _keys_in_category(c)) for c in _catalog_grouped().keys())
    }

    return jsonify({
        "hardening": hardening_state,
        "category_hardening": category_state,
        "redemption_counts": redemption_counts,
        "participants": participants,
        "total_redemptions": total_redemptions,
        "total_flags": len(CATALOG),
        "hardening_mode_all": hardening.FORCE_ALL,
    })


@bp.route("/api/toggle_flag", methods=["POST"])
@trainer_login_required
def api_toggle_flag():
    """Single-flag toggle -- the trainer role's own equivalent of
    app/ops.py's /ops/__set_hardening__. Needed because ops_bp isn't
    registered on the trainer-only process at all (see
    app/__init__.py's TRAINER_DASHBOARD branch) -- this is the same
    hardening.set_hardened() call, just reached through this
    blueprint's own auth instead."""
    if hardening.FORCE_ALL:
        abort(404)

    flag_key = request.form.get("flag_key") or (request.get_json(silent=True) or {}).get("flag_key")
    hardened_raw = request.form.get("hardened")
    if hardened_raw is None:
        hardened_raw = (request.get_json(silent=True) or {}).get("hardened")

    from .flags import VALID_KEYS
    if flag_key not in VALID_KEYS:
        abort(400, f"unknown flag_key: {flag_key!r}")

    hardened = str(hardened_raw).strip().lower() in ("1", "true", "yes", "on")
    hardening.set_hardened(flag_key, hardened)
    return jsonify({"flag_key": flag_key, "hardened": hardened})


@bp.route("/api/toggle_category", methods=["POST"])
@trainer_login_required
def api_toggle_category():
    """Next-phase item 2: one switch per category, flipping every flag
    key in that group -- via the exact same per-flag mechanism
    (hardening.set_hardened) the individual toggles already use, so
    there's no second, parallel hardening code path to keep in sync
    with the first."""
    if hardening.FORCE_ALL:
        abort(404)

    category = request.form.get("category") or (request.get_json(silent=True) or {}).get("category")
    hardened_raw = request.form.get("hardened")
    if hardened_raw is None:
        hardened_raw = (request.get_json(silent=True) or {}).get("hardened")
    hardened = str(hardened_raw).strip().lower() in ("1", "true", "yes", "on")

    keys = _keys_in_category(category or "")
    if not keys:
        abort(400, f"unknown category: {category!r}")

    for key in keys:
        hardening.set_hardened(key, hardened)

    return jsonify({"category": category, "hardened": hardened, "flag_keys": keys})


@bp.route("/leaderboard", methods=["GET"])
@trainer_login_required
def leaderboard():
    """Next-phase item 4: Participant Leaderboard -- participant
    progress/redemption standings, nickname-first. NOT the existing
    public solar leaderboard (app/leaderboard.py), which is a separate,
    unrelated over-exposure vulnerability and stays exactly as it is."""
    return render_template(
        "trainer_leaderboard.html",
        trainer_name=g.trainer["name"],
        participant_base_url=current_app.config.get("PARTICIPANT_BASE_URL", ""),
        total_flags=len(CATALOG),
    )


@bp.route("/api/leaderboard", methods=["GET"])
@trainer_login_required
def api_leaderboard():
    return jsonify({"standings": personalize.participant_standings(), "total_flags": len(CATALOG)})


@bp.route("/api/participant_checklist", methods=["GET"])
@trainer_login_required
def api_participant_checklist():
    """Phase 8: backs the leaderboard's "view redeemed flags" modal --
    one participant's full 48-flag checklist, same category/name/done
    shape and same CATALOG order as the participant-facing /progress
    page (app/progress.py), just for an arbitrary participant_id chosen
    by the instructor instead of g.participant_id. Only redemption
    status is returned, never a flag's actual value -- same as
    /progress itself, which never exposes other participants' values
    either."""
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


@bp.route("/reset", methods=["POST"])
@trainer_login_required
def reset_lab():
    """Trainer-side equivalent of app/ops.py's /ops/__reset_lab__ --
    same file-swap-then-regenerate-secret mechanism, operating on the
    SAME shared DB_PATH, just invoked from the trainer process instead
    of the participant one. See this module's docstring for the one
    known behavioral difference (in-memory counters on the participant
    side aren't reachable from here).

    Redirects back to the dashboard with a success/failure notice
    rather than returning a bare JSON body."""
    db_path = current_app.config["DB_PATH"]
    seed_path = os.environ.get("SEED_DB_PATH", "/app/data/seed.db")

    try:
        resets.reset_lab_state(db_path, seed_path)
    except Exception:
        current_app.logger.exception("Reset Lab failed")
        return _back_to("dashboard", notice="lab_reset_failed")

    return _back_to("dashboard", notice="lab_reset")


@bp.route("/reset_app", methods=["POST"])
@trainer_login_required
def reset_app():
    """Middle ground between Reset Lab and Reset All Redemptions: restores
    the app's own data (accounts, meters, tickets, ...) to the seeded state,
    returns every hardening toggle to vulnerable, expires every login
    session, and removes uploaded firmware files -- while keeping
    redemptions, participant IDs, nicknames and the flag secret exactly as
    they are. See app/resets.py."""
    db_path = current_app.config["DB_PATH"]
    seed_path = os.environ.get("SEED_DB_PATH", "/app/data/seed.db")

    try:
        resets.reset_app_state(db_path, seed_path)
    except Exception:
        current_app.logger.exception("Reset App failed")
        return _back_to("dashboard", notice="app_reset_failed")

    try:
        resets.clear_firmware_files()
    except Exception:
        current_app.logger.exception("Reset App: removing uploaded firmware files failed")
        return _back_to("dashboard", notice="app_reset_files_failed")

    return _back_to("dashboard", notice="app_reset")


@bp.route("/reset_redemptions", methods=["POST"])
@trainer_login_required
def reset_all_redemptions():
    """Clears every participant's flag_redemptions rows -- and nothing
    else (hardening state, nicknames, accounts, sessions all untouched;
    that's Reset Lab's job)."""
    try:
        db = get_db()
        removed = db.execute("DELETE FROM flag_redemptions").rowcount
        db.commit()
    except sqlite3.Error:
        current_app.logger.exception("Reset all redemptions failed")
        return _back_to("dashboard", notice="redemptions_reset_all_failed")
    return _back_to("dashboard", notice="redemptions_reset_all", n=removed)


@bp.route("/reset_redemption", methods=["POST"])
@trainer_login_required
def reset_participant_redemption():
    """Clears one participant's flag_redemptions rows by their full
    participant ID. Nicknames are deliberately left alone. Zero rows
    removed still counts as success (an ID with no redemptions is
    already in the requested state)."""
    next_name = request.form.get("next", "leaderboard")
    participant_id = (request.form.get("participant_id") or "").strip()
    if not participant_id:
        return _back_to(next_name, notice="redemptions_reset_no_id")
    try:
        db = get_db()
        removed = db.execute(
            "DELETE FROM flag_redemptions WHERE participant_id = ?", (participant_id,)
        ).rowcount
        db.commit()
    except sqlite3.Error:
        current_app.logger.exception("Reset redemption failed")
        return _back_to(next_name, notice="redemptions_reset_failed")
    return _back_to(next_name, notice="redemptions_reset", n=removed, pid=participant_id[:8])
