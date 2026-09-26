from flask import Blueprint, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db
from .flags import CATALOG, VALID_FLAGS

bp = Blueprint("progress", __name__)


@bp.route("/progress", methods=["GET", "POST"])
@login_required()
def progress():
    db = get_db()
    message = None

    if request.method == "POST":
        submitted = request.form.get("flag", "").strip()
        if submitted not in VALID_FLAGS:
            message = ("error", "Not a recognized flag.")
        else:
            existing = db.execute(
                "SELECT 1 FROM flag_redemptions WHERE flag_code = ?", (submitted,)
            ).fetchone()
            if existing:
                message = ("info", "Already redeemed — nice work, but no extra credit.")
            else:
                db.execute(
                    "INSERT INTO flag_redemptions (flag_code, redeemed_by) VALUES (?, ?)",
                    (submitted, g.user["email"]),
                )
                db.commit()
                message = ("success", "Correct! Flag redeemed.")

    redeemed = {
        row["flag_code"]
        for row in db.execute("SELECT flag_code FROM flag_redemptions").fetchall()
    }
    checklist = [
        {"category": category, "name": name, "done": code in redeemed}
        for code, category, name in CATALOG
    ]
    return render_template(
        "progress.html",
        checklist=checklist,
        done_count=len(redeemed),
        total_count=len(CATALOG),
        message=message,
    )
