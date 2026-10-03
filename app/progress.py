from flask import Blueprint, abort, g, jsonify, render_template, request

from .auth import login_required
from .code_examples import example_keys, example_payload
from .db import get_db
from .flags import CATALOG, REMEDIATION
from .personalize import get_flag
from . import hardening

bp = Blueprint("progress", __name__)


def _expected_flags_for(participant_id: str) -> dict[str, str]:
    """Each flag's expected value for this participant."""
    return {key: get_flag(key, participant_id) for key, _, _ in CATALOG}


@bp.route("/progress", methods=["GET", "POST"])
@login_required()
def progress():
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
    with_code = example_keys()
    checklist = [
        {"key": key, "category": category, "name": name, "done": key in redeemed, "has_code": key in with_code}
        for key, category, name in CATALOG
    ]
    return render_template(
        "progress.html",
        checklist=checklist,
        done_count=len(redeemed),
        total_count=len(CATALOG),
        message=message,
    )


@bp.route("/progress/code/<flag_key>")
@login_required()
def view_code(flag_key):
    """A flag's code example as JSON, available only once this participant has redeemed that flag."""
    if hardening.FORCE_ALL:
        abort(404)
    payload = example_payload(flag_key)
    if payload is None:
        abort(404)
    redeemed = get_db().execute(
        "SELECT 1 FROM flag_redemptions WHERE flag_key = ? AND participant_id = ?",
        (flag_key, g.participant_id),
    ).fetchone()
    if not redeemed:
        return jsonify({"error": "Redeem this flag to unlock its code."}), 403
    return jsonify(payload)
