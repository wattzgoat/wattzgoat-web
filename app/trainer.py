"""Phase 7: trainer dashboard -- a single admin-only page for running a
live class: toggle any flag's hardening state, reset the lab, and watch
participant progress update in real time, without needing raw curl
calls to /ops/__set_hardening__ or a manual per-participant /progress
check.

Its own blueprint under /trainer/, not folded into app/admin.py or
app/ops.py -- this is trainer-facing tooling, not part of the
vulnerable app surface itself, and keeping it separate means it could
eventually run under different auth (a dedicated trainer role, distinct
from "admin" in the lab's own fiction) without disturbing the admin
blueprint's own vulnerable-by-design routes.

Reuses app/ops.py's existing /ops/__set_hardening__ and
/ops/__hardening_status__ endpoints for the actual toggle mechanism --
nothing about hardening_state is duplicated here. This blueprint only
adds what those don't already expose: the flag catalog grouped for
display, and aggregate participant/redemption progress, both served
from one polled JSON endpoint so the page can update without a manual
reload.
"""
from flask import Blueprint, abort, jsonify, render_template

from .auth import login_required
from .db import get_db
from .flags import CATALOG
from . import hardening

bp = Blueprint("trainer", __name__, url_prefix="/trainer")


def _catalog_grouped():
    """CATALOG (key, category, name) tuples grouped by category, in
    catalog order -- the same grouping the instructor guide and
    progress.py use, so the dashboard's layout matches what a trainer
    already recognizes from the walkthrough."""
    grouped = {}
    for key, category, name in CATALOG:
        grouped.setdefault(category, []).append({"key": key, "name": name})
    return grouped


@bp.route("/", methods=["GET"])
@login_required(role="admin")
def dashboard():
    # A HARDENING_MODE=all instance never consults hardening_state at
    # all (see app/hardening.py's FORCE_ALL) -- every toggle this page
    # would show is permanently on and inert, same reasoning as
    # /progress being disabled there (see progress.py).
    if hardening.FORCE_ALL:
        abort(404)
    return render_template(
        "trainer_dashboard.html",
        grouped_catalog=_catalog_grouped(),
        total_flags=len(CATALOG),
    )


@bp.route("/api/summary", methods=["GET"])
@login_required(role="admin")
def api_summary():
    """Polled by the dashboard's JS every few seconds -- hardening
    state, redemption progress, and the participant roster, all in one
    call rather than three separate ones, to keep polling cheap. Every
    value here is safe to compute fresh on each call (no caching): the
    hardening table and flag_redemptions are both small, and staleness
    would be worse than the query cost for a live-class tool."""
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

    return jsonify({
        "hardening": hardening_state,
        "redemption_counts": redemption_counts,
        "participants": participants,
        "total_redemptions": total_redemptions,
        "total_flags": len(CATALOG),
        "hardening_mode_all": hardening.FORCE_ALL,
    })
