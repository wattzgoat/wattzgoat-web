import io
import math
import os
import sqlite3
import traceback

from flask import Blueprint, abort, g, make_response, redirect, render_template, request, send_file, url_for
from markupsafe import escape

from .auth import login_required, weak_hash, is_weak_password
from . import auth
from .db import get_db, mysql_style_error
from .devices import issue_device_token
from .hardening import csrf_token
from .personalize import get_flag
from . import billing
from . import flags
from . import hardening

bp = Blueprint("customer", __name__)

RECHARGE_RATE = 0.28    # $ per kWh credited on a normal top-up
SOLAR_CREDIT_RATE = 0.12  # $ credited per kWh of claimed solar export
BILLS_DIR = os.path.join(os.path.dirname(__file__), "bills")


def _own_meters():
    db = get_db()
    return db.execute(
        "SELECT * FROM meters WHERE user_id = ? ORDER BY id", (g.user["id"],)
    ).fetchall()


@bp.route("/dashboard")
@login_required(role="customer")
def dashboard():
    meters = _own_meters()
    device_tokens = {m["id"]: issue_device_token(m["meter_code"]) for m in meters}

    sessionid_flag = (
        get_flag(flags.SESSIONID_TEACH, g.participant_id)
        if g.user["email"] == flags.SESSIONID_ACCOUNT_EMAIL and not hardening.is_hardened(flags.SESSIONID_TEACH)
        else None
    )

    nickname_setter = next((m["nickname_set_by"] for m in meters if m["nickname_set_by"]), None)
    sxss_title_flag = (
        get_flag(flags.SXSS_TEACH, nickname_setter)
        if nickname_setter and not hardening.is_hardened(flags.SXSS_TEACH)
        else None
    )

    oldtoken_flag = None
    if auth._forged_reset_pending.get(g.user["id"]) == g.participant_id and not hardening.is_hardened(flags.OLDTOKEN_EXERCISE):
        oldtoken_flag = get_flag(flags.OLDTOKEN_EXERCISE, g.participant_id)
        del auth._forged_reset_pending[g.user["id"]]

    resp = make_response(render_template(
        "dashboard.html", user=g.user, meters=meters, device_tokens=device_tokens,
        sessionid_flag=sessionid_flag, sxss_title_flag=sxss_title_flag, oldtoken_flag=oldtoken_flag,
    ))
    if hardening.is_hardened(flags.HEADERS_TEACH):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    else:
        resp.headers["X-Lab-Flag"] = get_flag(flags.HEADERS_TEACH, g.participant_id)
    return resp


@bp.route("/meters/<int:meter_id>/nickname", methods=["POST"])
@login_required(role="customer")
def update_nickname(meter_id):
    if hardening.is_hardened(flags.CSRF_EXERCISE):
        submitted_token = request.form.get("csrf_token", "")
        if not submitted_token or submitted_token != csrf_token():
            abort(403)

    nickname = request.form.get("nickname", "")
    db = get_db()
    db.execute(
        "UPDATE meters SET nickname = ?, nickname_set_by = ? WHERE id = ? AND user_id = ?",
        (nickname, g.participant_id, meter_id, g.user["id"]),
    )
    db.commit()

    resp = make_response(redirect(url_for("customer.dashboard")))
    if _is_cross_origin(request) and not hardening.is_hardened(flags.CSRF_EXERCISE):
        resp.headers["X-Lab-Flag"] = get_flag(flags.CSRF_EXERCISE, g.participant_id)
    return resp


def _is_cross_origin(req) -> bool:
    own_origin = req.host_url.rstrip("/")
    origin = req.headers.get("Origin")
    if origin is not None:
        return origin != own_origin
    referer = req.headers.get("Referer")
    if referer is not None:
        return not referer.startswith(own_origin)
    return True


def _is_framed(req) -> bool:
    return req.headers.get("Sec-Fetch-Dest") == "iframe"


@bp.route("/account", methods=["GET"])
@login_required()
def account():
    return render_template("account.html", user=g.user)


@bp.route("/account/password", methods=["POST"])
@login_required()
def change_password():
    if hardening.is_hardened(flags.CSRF_TEACH):
        submitted_token = request.form.get("csrf_token", "")
        if not submitted_token or submitted_token != csrf_token():
            return render_template(
                "account.html", user=g.user,
                error="Missing or invalid security token -- request rejected.",
            ), 403

    new_password = request.form.get("new_password", "")

    confirm_new_password = request.form.get("confirm_new_password")
    if confirm_new_password is not None and new_password != confirm_new_password:
        return render_template("account.html", user=g.user, error="New passwords don't match.")

    if hardening.is_hardened(flags.PWCHANGE_TEACH):
        current_password = request.form.get("current_password", "")
        if weak_hash(current_password) != g.user["password_hash"]:
            return render_template(
                "account.html", user=g.user,
                error="Current password is incorrect.",
            ), 403

    if hardening.is_hardened(flags.WEAKPW_CHANGE) and is_weak_password(new_password):
        return render_template(
            "account.html", user=g.user,
            error="New password is too weak -- use at least 7 characters, mixing case, letters, and numbers.",
        )

    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak_hash(new_password), g.user["id"]))
    db.commit()

    weakpw_flag = (
        get_flag(flags.WEAKPW_CHANGE, g.participant_id)
        if is_weak_password(new_password) and not hardening.is_hardened(flags.WEAKPW_CHANGE)
        else None
    )
    pwchange_flag = (
        get_flag(flags.PWCHANGE_TEACH, g.participant_id)
        if len(new_password) > 7 and not hardening.is_hardened(flags.PWCHANGE_TEACH)
        else None
    )
    csrf_flag = (
        get_flag(flags.CSRF_TEACH, g.participant_id)
        if _is_cross_origin(request) and not hardening.is_hardened(flags.CSRF_TEACH)
        else None
    )

    return render_template(
        "account.html", user=g.user, password_changed=True,
        weakpw_flag=weakpw_flag, pwchange_flag=pwchange_flag, csrf_flag=csrf_flag,
    )


@bp.route("/recharge", methods=["GET", "POST"])
@login_required(role="customer")
def recharge():
    if request.method == "GET":
        meter = _own_meters()[0] if _own_meters() else None
        return render_template("recharge.html", meter=meter, rate=RECHARGE_RATE)

    meters = _own_meters()
    if not meters:
        return redirect(url_for("customer.dashboard"))
    meter = meters[0]
    try:
        amount_paid = float(request.form.get("amount_paid", 0) or 0)
    except ValueError:
        tb = traceback.format_exc() + f"\n# improper error handling instance: {get_flag(flags.INFOLEAK_TEACH, g.participant_id)}"
        return render_template("error_debug.html", traceback=tb), 500

    if hardening.is_hardened(flags.BUSLOGIC_NEGATIVE_RECHARGE):
        if not math.isfinite(amount_paid) or amount_paid <= 0:
            return render_template(
                "recharge.html", meter=meter, rate=RECHARGE_RATE,
                error="Enter an amount greater than $0.00.",
            ), 400
        negative_flag = None
    else:
        negative_flag = get_flag(flags.BUSLOGIC_NEGATIVE_RECHARGE, g.participant_id) if amount_paid < 0 else None

    raw_override = request.form.get("units_credited")
    if hardening.is_hardened(flags.BUSLOGIC_TEACH):
        units_credited = round(amount_paid / RECHARGE_RATE, 2)
        buslogic_flag = None
    else:
        units_credited = float(raw_override) if raw_override not in (None, "") else round(amount_paid / RECHARGE_RATE, 2)
        buslogic_flag = get_flag(flags.BUSLOGIC_TEACH, g.participant_id) if raw_override not in (None, "") else None

    db = get_db()
    credited_meter = meter
    clickjack_flag = None
    target_code = request.form.get("target_meter_code")
    if target_code and not hardening.is_hardened(flags.HEADERS_CLICKJACK):
        other = db.execute("SELECT * FROM meters WHERE meter_code = ?", (target_code,)).fetchone()
        if other is not None and other["id"] != meter["id"]:
            credited_meter = other
            if _is_framed(request):
                clickjack_flag = get_flag(flags.HEADERS_CLICKJACK, g.participant_id)

    db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (units_credited, credited_meter["id"]))
    db.execute(
        "INSERT INTO recharges (user_id, amount_paid, units_credited) VALUES (?, ?, ?)",
        (g.user["id"], amount_paid, units_credited),
    )
    db.commit()
    meter = _own_meters()[0]
    return render_template(
        "recharge.html", meter=meter, rate=RECHARGE_RATE, paid=amount_paid, credited=units_credited,
        buslogic_flag=buslogic_flag, negative_flag=negative_flag, clickjack_flag=clickjack_flag,
    )


@bp.route("/solar", methods=["GET", "POST"])
@login_required(role="customer")
def solar():
    if request.method == "GET":
        meter = _own_meters()[0] if _own_meters() else None
        return render_template("solar.html", meter=meter, export_rate=SOLAR_CREDIT_RATE, rate=RECHARGE_RATE)

    meters = _own_meters()
    if not meters:
        return redirect(url_for("customer.dashboard"))
    meter = meters[0]
    exported_kwh = float(request.form.get("exported_kwh", 0) or 0)

    if hardening.is_hardened(flags.BUSLOGIC_NEGATIVE_SOLAR):
        if not math.isfinite(exported_kwh) or exported_kwh <= 0:
            return render_template(
                "solar.html", meter=meter, export_rate=SOLAR_CREDIT_RATE, rate=RECHARGE_RATE,
                error="Enter an export greater than 0 kWh.",
            ), 400
        negative_flag = None
    else:
        negative_flag = get_flag(flags.BUSLOGIC_NEGATIVE_SOLAR, g.participant_id) if exported_kwh < 0 else None
    if hardening.is_hardened(flags.BUSLOGIC_EXERCISE) and exported_kwh > 1000:
        exported_kwh = 1000
    credit_amount = round(exported_kwh * SOLAR_CREDIT_RATE, 2)
    units_credited = round(credit_amount / RECHARGE_RATE, 2)
    buslogic_flag = (
        get_flag(flags.BUSLOGIC_EXERCISE, g.participant_id)
        if exported_kwh > 1000 and not hardening.is_hardened(flags.BUSLOGIC_EXERCISE)
        else None
    )

    db = get_db()
    db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (units_credited, meter["id"]))
    db.execute(
        "INSERT INTO solar_exports (user_id, exported_kwh, credit_amount) VALUES (?, ?, ?)",
        (g.user["id"], exported_kwh, credit_amount),
    )
    db.commit()
    meter = _own_meters()[0]
    return render_template(
        "solar.html", meter=meter, export_rate=SOLAR_CREDIT_RATE, rate=RECHARGE_RATE,
        exported=exported_kwh, credit=credit_amount, credited=units_credited,
        buslogic_flag=buslogic_flag, negative_flag=negative_flag,
    )


@bp.route("/usage", methods=["GET"])
@login_required(role="customer")
def usage():
    query = request.args.get("q", "")
    if not query:
        return render_template("usage.html", query=None, results=None, db_error=None)

    meter = _own_meters()[0] if _own_meters() else None
    meter_id = meter["id"] if meter else -1

    db = get_db()
    sqli_flag = None
    if hardening.is_hardened(flags.SQLI_BONUS) or hardening.is_hardened(flags.SQLI_BOOLEAN_BONUS):
        sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?"
        params = (meter_id, f"%{query}%")
    else:
        sql = f"SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = {meter_id} AND recorded_at LIKE '%{query}%'"
        params = ()

    try:
        results = db.execute(sql, params).fetchall()
        db_error = None
        if results and any(
            flags.SQLI_BONUS_SENTINEL in str(value) for row in results for value in tuple(row)
        ):
            if "union" in query.lower():
                sqli_flag = get_flag(flags.SQLI_BONUS, g.participant_id)
            else:
                sqli_flag = get_flag(flags.SQLI_BOOLEAN_BONUS, g.participant_id)
    except sqlite3.OperationalError as e:
        results = None
        if hardening.is_hardened(flags.ERRHANDLING_TEACH):
            db_error = "Something went wrong processing your search. Please try again."
        else:
            db_error = mysql_style_error(e) + f"\n-- improper error handling: {get_flag(flags.ERRHANDLING_TEACH, g.participant_id)}"

    query_display = escape(query) if hardening.is_hardened(flags.RXSS_TEACH) else query
    return render_template(
        "usage.html", query=query_display, results=results, db_error=db_error, sqli_flag=sqli_flag
    )


@bp.route("/support", methods=["GET", "POST"])
@login_required(role="customer")
def support():
    db = get_db()
    if request.method == "POST":
        subject = request.form.get("subject", "")
        description = request.form.get("description", "")
        db.execute(
            "INSERT INTO tickets (user_id, subject, description, participant_id) VALUES (?, ?, ?, ?)",
            (g.user["id"], subject, description, g.participant_id),
        )
        db.commit()

    tickets = db.execute(
        "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("support.html", tickets=tickets)


@bp.route("/bills")
@login_required(role="customer")
def bills():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM bills WHERE user_id = ? ORDER BY period DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("bills.html", bills=rows)


@bp.route("/bills/download")
@login_required(role="customer")
def download_bill():
    rel_path = request.args.get("path", "")
    full_path = os.path.normpath(os.path.join(BILLS_DIR, rel_path))

    real_bills_dir = os.path.realpath(BILLS_DIR)
    real_full_path = os.path.realpath(full_path)
    if os.path.commonpath([real_bills_dir, real_full_path]) != real_bills_dir:
        abort(403)

    if hardening.is_hardened(flags.TRAVERSAL_TEACH):
        own_meter_codes = {m["meter_code"] for m in _own_meters()}
        rel_to_bills = os.path.relpath(real_full_path, real_bills_dir)
        requested_meter_code = rel_to_bills.split(os.sep)[0]
        if requested_meter_code not in own_meter_codes:
            abort(403)

    if os.path.isdir(full_path):
        try:
            entries = sorted(os.listdir(full_path))
        except OSError:
            abort(404)
        parent = os.path.normpath(os.path.join(rel_path, ".."))
        return render_template("bill_directory_listing.html", rel_path=rel_path or ".", parent=parent, entries=entries)

    if not os.path.isfile(full_path):
        abort(404)

    ben_bill_path = os.path.normpath(os.path.join(BILLS_DIR, billing.BEN_METER_CODE, f"{billing.BILL_PERIOD}.pdf"))
    if full_path == ben_bill_path:
        pdf_bytes = billing.draw_ben_bill_pdf(get_flag(flags.TRAVERSAL_TEACH, g.participant_id))
        return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf", download_name=f"{billing.BILL_PERIOD}.pdf")

    return send_file(full_path, mimetype="application/pdf")
