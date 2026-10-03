from flask import Blueprint, jsonify, render_template

from .db import get_db

bp = Blueprint("leaderboard", __name__)



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
