from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db
from .flags import CATALOG, REMEDIATION
from .personalize import get_flag
from . import hardening

bp = Blueprint("progress", __name__)


def _expected_flags_for(participant_id: str) -> dict[str, str]:
    """Every flag key's expected value for this participant, computed
    fresh each call (no caching) -- these are cheap HMAC operations, and
    caching would need to be invalidated on every lab reset anyway (see
    personalize.regenerate_lab_secret), so it isn't worth the complexity."""
    return {key: get_flag(key, participant_id) for key, _, _ in CATALOG}


@bp.route("/progress", methods=["GET", "POST"])
@login_required()
def progress():
    # Phase 6: a HARDENING_MODE=all instance disables flag redemption
    # entirely rather than leaving it up and letting every submission
    # fail -- per the project owner's call, a working /progress on a
    # fully-hardened reference instance would just confuse participants
    # ("is this broken, or is nothing here findable on purpose?").
    # Disabled as a flat 404, not a message -- this route genuinely isn't
    # part of what a hardened instance offers, same as it isn't wired
    # into base.html's nav for one either (see base.html).
    if hardening.FORCE_ALL:
        abort(404)

    db = get_db()
    message = None

    if request.method == "POST":
        submitted = request.form.get("flag", "").strip()
        expected = _expected_flags_for(g.participant_id)
        matched_key = next((key for key, value in expected.items() if value == submitted), None)

        if matched_key is None:
            message = ("error", "Not a recognized flag.")
        else:
            existing = db.execute(
                "SELECT 1 FROM flag_redemptions WHERE flag_key = ? AND participant_id = ?",
                (matched_key, g.participant_id),
            ).fetchone()
            if existing:
                message = ("info", "Already redeemed — nice work, but no extra credit.")
            else:
                db.execute(
                    "INSERT INTO flag_redemptions (flag_key, participant_id, redeemed_by) VALUES (?, ?, ?)",
                    (matched_key, g.participant_id, g.user["email"]),
                )
                db.commit()
                note = REMEDIATION.get(matched_key)
                text = "Correct! Flag redeemed."
                if note:
                    text += f" Fix: {note}"
                message = ("success", text)

    redeemed = {
        row["flag_key"]
        for row in db.execute(
            "SELECT flag_key FROM flag_redemptions WHERE participant_id = ?", (g.participant_id,)
        ).fetchall()
    }
    checklist = [
        {"category": category, "name": name, "done": key in redeemed}
        for key, category, name in CATALOG
    ]
    return render_template(
        "progress.html",
        checklist=checklist,
        done_count=len(redeemed),
        total_count=len(CATALOG),
        message=message,
    )
