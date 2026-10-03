"""The instructor dashboard: toggle vulnerabilities, offer guided mode, watch progress and reset the lab. It runs as its own process, separate from the participant app."""
import os
import sqlite3

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from .code_examples import example_keys, example_payload
from .db import get_db
from .flags import CATALOG
from . import export
from . import guided
from . import hardening
from . import personalize
from . import resets
from . import trainer_auth
from .trainer_auth import trainer_login_required

bp = Blueprint("trainer", __name__, url_prefix="/instructor")


def _catalog_grouped():
    """Flags grouped by category, in catalog order."""
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
    if hardening.FORCE_ALL:
        abort(404)
    return render_template(
        "trainer_dashboard.html",
        grouped_catalog=_catalog_grouped(),
        categories=list(_catalog_grouped().keys()),
        total_flags=len(CATALOG),
        guided_enabled=guided.setting_enabled(),
        trainer_name=g.trainer["name"],
        participant_base_url=current_app.config.get("PARTICIPANT_BASE_URL", ""),
    )


@bp.route("/export/summary.csv", methods=["GET"])
@trainer_login_required
def export_summary():
    return export.summary_response()


@bp.route("/export/detail.csv", methods=["GET"])
@trainer_login_required
def export_detail():
    return export.detail_response()


@bp.route("/code", methods=["GET"])
@trainer_login_required
def code_examples():
    """The Code Examples page: vulnerable and fixed code for every flag."""
    with_code = example_keys()
    grouped = {
        category: [{**item, "has_code": item["key"] in with_code} for item in items]
        for category, items in _catalog_grouped().items()
    }
    return render_template(
        "trainer_code.html",
        grouped_catalog=grouped,
        trainer_name=g.trainer["name"],
        participant_base_url=current_app.config.get("PARTICIPANT_BASE_URL", ""),
    )


@bp.route("/api/code_example", methods=["GET"])
@trainer_login_required
def api_code_example():
    payload = example_payload(request.args.get("flag_key", ""))
    if payload is None:
        abort(404)
    return jsonify(payload)


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
        "guided_mode_enabled": guided.setting_enabled(),
    })


@bp.route("/api/guided_mode", methods=["POST"])
@trainer_login_required
def api_guided_mode():
    """Switch guided mode on or off for participants on every instance that
    shares this data. On only OFFERS it: each participant still chooses
    whether to turn it on in their own browser."""
    if hardening.FORCE_ALL:
        abort(404)
    raw = request.form.get("enabled")
    if raw is None:
        raw = (request.get_json(silent=True) or {}).get("enabled")
    if str(raw).lower() not in ("1", "0", "true", "false"):
        abort(400, "enabled must be 1 or 0")
    enabled = str(raw).lower() in ("1", "true")
    guided.set_setting(enabled)
    return jsonify({"enabled": enabled})


@bp.route("/api/toggle_flag", methods=["POST"])
@trainer_login_required
def api_toggle_flag():
    """Switch one flag between vulnerable and fixed."""
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
    """Switch every flag in a category between vulnerable and fixed."""
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
    """The participant leaderboard."""
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
    """One participant's flag checklist, as JSON."""
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
    """Restore the whole lab to its seeded state."""
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
    """Restore the app's own data to its seeded state, keeping progress."""
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
    """Clear one participant's progress."""
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
