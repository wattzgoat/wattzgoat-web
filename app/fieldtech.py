from flask import Blueprint, g, jsonify, render_template, request

from . import flags
from . import hardening
from .db import get_db
from .personalize import get_flag

bp = Blueprint("fieldtech", __name__)



@bp.route("/tools/meter-lookup")
def meter_lookup_page():
    return render_template("meter_lookup.html")


@bp.route("/api/field/meter-lookup")
def meter_lookup_api():
    code = request.args.get("code", "").strip()
    if not code:
        return jsonify({"error": "code is required"}), 400

    db = get_db()
    meter = db.execute(
        "SELECT meters.*, users.id AS owner_id, users.email AS owner_email, users.name AS owner_name, "
        "users.role AS owner_role, users.address_service AS owner_address_service, "
        "users.address_billing AS owner_address_billing, users.billing_rate AS owner_billing_rate, "
        "users.created_at AS owner_created_at "
        "FROM meters JOIN users ON users.id = meters.user_id WHERE meters.meter_code = ?",
        (code,),
    ).fetchone()
    if meter is None:
        return jsonify({"error": f"no meter found with code {code}"}), 404

    row = dict(meter)

    if hardening.is_hardened(flags.FIELDTECH_LOOKUP):
        return jsonify({
            "meter_code": row["meter_code"],
            "status": row["status"],
            "install_address": row["owner_address_service"],
        })

    return jsonify({
        "meter_code": row["meter_code"],
        "status": row["status"],
        "install_address": row["owner_address_service"],
        "owner": {
            "id": row["owner_id"],
            "email": row["owner_email"],
            "name": row["owner_name"],
            "role": row["owner_role"],
            "billing_address": row["owner_address_billing"],
            "billing_rate": row["owner_billing_rate"],
            "account_created_at": row["owner_created_at"],
        },
        "balance": row["balance"],
        "flag": get_flag(flags.FIELDTECH_LOOKUP, g.participant_id),
    })
