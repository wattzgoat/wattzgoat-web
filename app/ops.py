from flask import Blueprint, abort, jsonify, request

from . import auth, flags, hardening

bp = Blueprint("ops", __name__, url_prefix="/ops")


@bp.route("/__set_hardening__", methods=["POST"])
@auth.login_required(role="admin")
def set_hardening():
    flag_key = request.form.get("flag_key") or (request.get_json(silent=True) or {}).get("flag_key")
    hardened_raw = request.form.get("hardened")
    if hardened_raw is None:
        hardened_raw = (request.get_json(silent=True) or {}).get("hardened")

    if flag_key not in flags.VALID_KEYS:
        abort(400, f"unknown flag_key: {flag_key!r}")

    hardened = str(hardened_raw).strip().lower() in ("1", "true", "yes", "on")
    hardening.set_hardened(flag_key, hardened)
    return jsonify({"flag_key": flag_key, "hardened": hardened})
