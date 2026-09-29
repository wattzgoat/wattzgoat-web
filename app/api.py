from flask import Blueprint, abort, g, jsonify, request

from . import flags
from . import hardening
from .auth import login_required
from .db import get_db
from .devices import verify_device_token
from .personalize import get_flag

bp = Blueprint("api", __name__, url_prefix="/api")

# Fields the account page's form is meant to expose. billing_rate is an
# internal figure the operator console sets, not something a customer
# should be able to touch -- but it's still in this list, the way a
# leftover field from an earlier internal tool tends to survive a copy
# paste. That's the "broken object-property-level access control" exercise
# instance. `role` is the same story, one level worse -- a customer who
# sets their own role to 'admin' this way gets real admin access, the
# broken-access-control bonus third instance.
ACCOUNT_PATCHABLE_FIELDS = {"name", "phone", "address_service", "address_billing", "billing_rate", "role"}


@bp.route("/account", methods=["PATCH"])
@login_required()
def patch_account():
    payload = request.get_json(silent=True) or {}

    # Phase 6: MASSASSIGN_EXERCISE and ROLE_ESCALATION_BONUS are two
    # independent toggles on the SAME allow-list, gating two different
    # fields that shouldn't be here -- billing_rate (an internal figure)
    # and role (real privilege). Hardening one drops just that field from
    # what's patchable; hardening both collapses this back to what the
    # form actually exposes.
    patchable_fields = set(ACCOUNT_PATCHABLE_FIELDS)
    if hardening.is_hardened(flags.MASSASSIGN_EXERCISE):
        patchable_fields.discard("billing_rate")
    if hardening.is_hardened(flags.ROLE_ESCALATION_BONUS):
        patchable_fields.discard("role")

    db = get_db()

    # NOTE: account_email isn't a database column this route ever writes
    # -- it's a THIRD hidden field on the account form (account.html),
    # pre-filled with the caller's own address, that decides which row
    # every other field in this same payload gets written to. Point it at
    # someone else's email and their account is the one that gets
    # updated, not the caller's -- broken access control bonus instance
    # (a fourth, alongside the readings-API IDOR and the two mass-
    # assignment flags already on this same page).
    #
    # Phase 6: hardened branch ignores this field outright, the same
    # pattern as billing_rate/role above -- always the caller's own row.
    target = g.user
    is_idor = False
    target_email = payload.get("account_email")
    if target_email and not hardening.is_hardened(flags.ACCOUNT_IDOR_BONUS):
        other = db.execute("SELECT * FROM users WHERE email = ?", (target_email,)).fetchone()
        if other is not None and other["id"] != g.user["id"]:
            target = other
            is_idor = True

    updates = {k: v for k, v in payload.items() if k in patchable_fields}
    if not updates:
        return jsonify({"error": "no recognized fields in payload"}), 400

    if "role" in updates and updates["role"] not in ("customer", "admin"):
        return jsonify({"error": "invalid role"}), 400

    was_customer = target["role"] == "customer"
    # Phase 7: MASSASSIGN_EXERCISE only fires when billing_rate actually
    # changes -- account.html sends it as a hidden field on EVERY save
    # (including ones that only touch name/phone/address), so firing on
    # mere presence awarded the flag on completely unrelated edits.
    old_billing_rate = target["billing_rate"]

    set_clause = ", ".join(f"{field} = ?" for field in updates)
    db.execute(
        f"UPDATE users SET {set_clause} WHERE id = ?",
        (*updates.values(), target["id"]),
    )
    db.commit()

    result = {"updated": list(updates.keys())}
    if is_idor:
        # A request that reaches another account at all is the finding --
        # which specific fields it also touched doesn't earn the
        # mass-assignment/role flags on top, or one tampered request
        # could claim three flags at once.
        result["idor_flag"] = get_flag(flags.ACCOUNT_IDOR_BONUS, g.participant_id)
    else:
        if "billing_rate" in updates and float(updates["billing_rate"]) != float(old_billing_rate):
            result["flag"] = get_flag(flags.MASSASSIGN_EXERCISE, g.participant_id)
        if "role" in updates and updates["role"] == "admin" and was_customer:
            result["role_flag"] = get_flag(flags.ROLE_ESCALATION_BONUS, g.participant_id)
    return jsonify(result)


@bp.route("/meters/<int:meter_id>/readings", methods=["GET"])
@login_required()
def meter_readings(meter_id):
    # NOTE: no check that meter_id actually belongs to g.user -- IDOR teach
    # instance. Any logged-in customer can page through every meter_id and
    # see someone else's nickname, balance, and connection status.
    db = get_db()
    meter = db.execute(
        "SELECT id, meter_code, nickname, status, balance, user_id FROM meters WHERE id = ?",
        (meter_id,),
    ).fetchone()
    if meter is None:
        # A "helpful" 404 that leaks the fleet's internal ID range. Left
        # in as-is (no flag attached) -- handy for an attacker figuring
        # out how many meters/accounts exist without needing the IDOR
        # above at all, same "unflagged, worth noticing" spirit as a
        # couple of other spots in this app.
        max_id = db.execute("SELECT MAX(id) FROM meters").fetchone()[0] or 0
        return jsonify(
            {"error": f"no meter with internal id {meter_id} (valid range for this fleet is 1-{max_id})"}
        ), 404

    readings = db.execute(
        "SELECT reading_kwh, source, recorded_at FROM readings "
        "WHERE meter_id = ? ORDER BY recorded_at DESC LIMIT 100",
        (meter_id,),
    ).fetchall()

    meter_dict = dict(meter)
    is_idor = meter_dict.pop("user_id") != g.user["id"]

    # Phase 6: hardened branch actually enforces ownership (or admin
    # role) instead of just withholding the flag while still returning
    # someone else's meter data.
    if is_idor and hardening.is_hardened(flags.IDOR_TEACH) and g.user["role"] != "admin":
        abort(403)

    response = {
        "meter": meter_dict,
        "readings": [dict(r) for r in readings],
    }
    if is_idor and not hardening.is_hardened(flags.IDOR_TEACH):
        response["flag"] = get_flag(flags.IDOR_TEACH, g.participant_id)
    return jsonify(response)


@bp.route("/telemetry", methods=["POST"])
def telemetry():
    # NOTE: this is a device endpoint, not a customer-session one -- its
    # only "auth" is the JWT. Since the token's own meter_code claim
    # decides which meter the reading gets attributed to, and alg=none
    # lets that claim be anything (see app/devices.py), this is a complete
    # impersonate-any-meter-and-inject-a-reading exploit chain by itself.
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    meter_code, used_none_alg = verify_device_token(token)
    if meter_code is None:
        return jsonify({"error": "invalid device token"}), 401

    db = get_db()
    meter = db.execute("SELECT id FROM meters WHERE meter_code = ?", (meter_code,)).fetchone()
    if meter is None:
        return jsonify({"error": "unknown meter"}), 404

    payload = request.get_json(silent=True) or {}
    try:
        reading_kwh = float(payload.get("reading_kwh"))
    except (TypeError, ValueError):
        return jsonify({"error": "reading_kwh must be a number"}), 400

    db.execute(
        "INSERT INTO readings (meter_id, reading_kwh, source) VALUES (?, ?, 'simulator')",
        (meter["id"], reading_kwh),
    )
    db.commit()

    result = {"status": "ok"}
    if used_none_alg:
        # Insecure JWT exercise instance.
        result["flag"] = get_flag(flags.JWT_EXERCISE, g.participant_id)
    # Same routes served unencrypted on port 5001 as on HTTPS 5000 (see
    # run.py) -- plaintext transmission exercise instance: this Bearer
    # token and the reading it authorizes went out in the clear.
    if request.environ.get("SERVER_PORT") == "5001":
        result["plaintext_flag"] = get_flag(flags.PLAINTEXT_EXERCISE, g.participant_id)
    return jsonify(result)
