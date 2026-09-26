from flask import Blueprint, jsonify, render_template

from .db import get_db

bp = Blueprint("leaderboard", __name__)

# Public and unauthenticated on purpose -- a "top solar exporters this
# month" page is a plausible real feature for a utility to publish with no
# login. Linked from the pre-login nav and the admin console; never shown
# to a logged-in customer. Deliberately unflagged -- an "advanced
# discovery" bonus path, same spirit as the /usage SQL injection
# side-channel, for a participant who inspects the API response rather
# than just the rendered page. Unlike the field-technician lookup (which
# deliberately excludes password_hash to avoid fully overlapping with the
# SQL injection category), this one includes it.


@bp.route("/leaderboard")
def leaderboard_page():
    return render_template("leaderboard.html")


@bp.route("/api/leaderboard")
def leaderboard_api():
    db = get_db()
    rows = db.execute(
        "SELECT users.name, users.email, users.password_hash, users.role, "
        "COALESCE(SUM(solar_exports.exported_kwh), 0) AS total_exported_kwh "
        "FROM users LEFT JOIN solar_exports ON solar_exports.user_id = users.id "
        "WHERE users.role = 'customer' "
        "GROUP BY users.id ORDER BY total_exported_kwh DESC LIMIT 10"
    ).fetchall()
    return jsonify([dict(r) for r in rows])
