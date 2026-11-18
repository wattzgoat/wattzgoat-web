import os
import subprocess

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .auth import login_required, weak_hash
from .db import get_db
from .personalize import get_flag
from . import flags
from . import hardening
from .resets import firmware_dir

bp = Blueprint("admin", __name__, url_prefix="/admin")

FIRMWARE_DIR = firmware_dir()
CANARY_PATH = os.path.normpath(os.path.join(FIRMWARE_DIR, "canary.txt"))


@bp.route("/")
@login_required(role="admin")
def dashboard():
    db = get_db()
    stats = {
        "meter_count": db.execute("SELECT COUNT(*) FROM meters").fetchone()[0],
        "connected_count": db.execute("SELECT COUNT(*) FROM meters WHERE status='connected'").fetchone()[0],
        "customer_count": db.execute("SELECT COUNT(*) FROM users WHERE role='customer'").fetchone()[0],
        "open_tickets": db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
    }
    weakpw_flag = get_flag(flags.WEAKPW_EXERCISE, g.participant_id) if g.user["password_hash"] == weak_hash("changeme") else None
    devadmin_flag = (
        get_flag(flags.DEVADMIN_LEAK, g.participant_id)
        if g.user["email"] == flags.DEVADMIN_ACCOUNT_EMAIL and not hardening.is_hardened(flags.DEVADMIN_LEAK)
        else None
    )
    return render_template(
        "admin_dashboard.html", user=g.user, stats=stats, weakpw_flag=weakpw_flag, devadmin_flag=devadmin_flag
    )


@bp.route("/meters")
@login_required(role="admin")
def meters():
    query = request.args.get("q", "")
    db = get_db()
    if hardening.is_hardened(flags.SQLI_TEACH):
        if query:
            sql = (
                "SELECT meters.*, users.name AS owner_name, users.email AS owner_email "
                "FROM meters JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "WHERE meters.meter_code LIKE ? OR users.email LIKE ?"
            )
            rows = db.execute(sql, (f"%{query}%", f"%{query}%")).fetchall()
        else:
            sql = (
                "SELECT meters.*, users.name AS owner_name, users.email AS owner_email "
                "FROM meters JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "ORDER BY meters.id"
            )
            rows = db.execute(sql).fetchall()
    else:
        if query:
            sql = (
                "SELECT meters.*, users.name AS owner_name, users.email AS owner_email "
                "FROM meters JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                f"WHERE meters.meter_code LIKE '%{query}%' OR users.email LIKE '%{query}%'"
            )
        else:
            sql = (
                "SELECT meters.*, users.name AS owner_name, users.email AS owner_email "
                "FROM meters JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "ORDER BY meters.id"
            )
        rows = db.execute(sql).fetchall()

    sqli_flag = None
    if rows and any(flags.SQLI_TEACH_SENTINEL in str(value) for row in rows for value in tuple(row)):
        sqli_flag = get_flag(flags.SQLI_TEACH, g.participant_id)
    return render_template("admin_meters.html", meters=rows, query=query, sqli_flag=sqli_flag)


@bp.route("/meters/<int:meter_id>")
@login_required(role="admin")
def meter_detail(meter_id):
    db = get_db()
    meter = db.execute(
        "SELECT meters.*, users.name AS owner_name, users.email AS owner_email "
        "FROM meters JOIN users ON users.id = meters.user_id WHERE meters.id = ?",
        (meter_id,),
    ).fetchone()
    if meter is None:
        return redirect(url_for("admin.meters"))
    readings = db.execute(
        "SELECT reading_kwh, source, recorded_at FROM readings "
        "WHERE meter_id = ? ORDER BY recorded_at DESC LIMIT 10",
        (meter_id,),
    ).fetchall()
    return render_template("admin_meter_detail.html", meter=meter, readings=readings)


@bp.route("/meters/<int:meter_id>/firmware", methods=["POST"])
@login_required(role="admin")
def upload_firmware(meter_id):
    db = get_db()
    meter = db.execute("SELECT meter_code FROM meters WHERE id = ?", (meter_id,)).fetchone()
    if meter is None:
        return redirect(url_for("admin.meters"))

    uploaded = request.files.get("firmware")
    if uploaded is None or uploaded.filename == "":
        return redirect(url_for("admin.meter_detail", meter_id=meter_id))

    if hardening.is_hardened(flags.FILEUPLOAD_TEACH):
        ext = os.path.splitext(uploaded.filename)[1].lower()
        uploaded.stream.seek(0, os.SEEK_END)
        size = uploaded.stream.tell()
        uploaded.stream.seek(0)
        if ext not in (".bin", ".hex") or size > 2 * 1024 * 1024:
            return render_template(
                "firmware_uploaded.html", meter_code=meter["meter_code"], filename=uploaded.filename,
                flag=None, error="Rejected: firmware must be a .bin or .hex file under 2 MB.",
            ), 400

    save_filename = os.path.basename(uploaded.filename) if hardening.is_hardened(flags.FILEUPLOAD_EXERCISE) else uploaded.filename
    save_path = os.path.normpath(os.path.join(FIRMWARE_DIR, meter["meter_code"], save_filename))
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    uploaded.save(save_path)

    fileupload_flag = None
    intended_dir = os.path.normpath(os.path.join(FIRMWARE_DIR, meter["meter_code"]))
    real_intended_dir = os.path.realpath(intended_dir)
    real_save_path = os.path.realpath(save_path)
    if os.path.commonpath([real_intended_dir, real_save_path]) != real_intended_dir:
        fileupload_flag = get_flag(flags.FILEUPLOAD_EXERCISE, g.participant_id)
    elif os.path.dirname(save_path) == intended_dir:
        fileupload_flag = get_flag(flags.FILEUPLOAD_TEACH, g.participant_id)

    return render_template("firmware_uploaded.html", meter_code=meter["meter_code"], filename=uploaded.filename, flag=fileupload_flag)


@bp.route("/firmware-canary")
@login_required(role="admin")
def firmware_canary():
    try:
        with open(CANARY_PATH, "r", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        content = "(untouched -- nothing has overwritten this file yet)"
    return render_template("firmware_canary.html", content=content)


@bp.route("/meters/<int:meter_id>/disconnect", methods=["POST"])
@login_required()
def disconnect_meter(meter_id):
    db = get_db()
    meter = db.execute("SELECT user_id FROM meters WHERE id = ?", (meter_id,)).fetchone()
    is_escalation = meter is not None and g.user["role"] != "admin" and meter["user_id"] != g.user["id"]

    if is_escalation and hardening.is_hardened(flags.PRIVESC_TEACH):
        abort(403)

    db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter_id,))
    db.commit()

    if is_escalation:
        return render_template("privesc_done.html", action="disconnected", flag=get_flag(flags.PRIVESC_TEACH, g.participant_id))
    return redirect(request.referrer or url_for("admin.meters"))


@bp.route("/meters/<int:meter_id>/reconnect", methods=["POST"])
@login_required()
def reconnect_meter(meter_id):
    db = get_db()
    meter = db.execute("SELECT user_id FROM meters WHERE id = ?", (meter_id,)).fetchone()
    is_escalation = meter is not None and g.user["role"] != "admin" and meter["user_id"] != g.user["id"]

    if is_escalation and hardening.is_hardened(flags.PRIVESC_TEACH):
        abort(403)

    db.execute("UPDATE meters SET status = 'connected' WHERE id = ?", (meter_id,))
    db.commit()

    if is_escalation:
        return render_template("privesc_done.html", action="reconnected", flag=get_flag(flags.PRIVESC_TEACH, g.participant_id))
    return redirect(request.referrer or url_for("admin.meters"))


@bp.route("/alarms")
@login_required(role="admin")
def alarms():
    query = request.args.get("q", "")
    db = get_db()
    if hardening.is_hardened(flags.SQLI_EXERCISE):
        if query:
            sql = (
                "SELECT alarms.*, meters.meter_code FROM alarms "
                "JOIN meters ON meters.id = alarms.meter_id "
                "JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "WHERE alarms.type LIKE ? OR alarms.message LIKE ?"
            )
            rows = db.execute(sql, (f"%{query}%", f"%{query}%")).fetchall()
        else:
            sql = (
                "SELECT alarms.*, meters.meter_code FROM alarms "
                "JOIN meters ON meters.id = alarms.meter_id "
                "JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "ORDER BY alarms.created_at DESC"
            )
            rows = db.execute(sql).fetchall()
    else:
        if query:
            sql = (
                "SELECT alarms.*, meters.meter_code FROM alarms "
                "JOIN meters ON meters.id = alarms.meter_id "
                "JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                f"WHERE alarms.type LIKE '%{query}%' OR alarms.message LIKE '%{query}%'"
            )
        else:
            sql = (
                "SELECT alarms.*, meters.meter_code FROM alarms "
                "JOIN meters ON meters.id = alarms.meter_id "
                "JOIN users ON users.id = meters.user_id AND users.role != 'service' "
                "ORDER BY alarms.created_at DESC"
            )
        rows = db.execute(sql).fetchall()
    sqli_flag = None
    if rows and any(flags.SQLI_EXERCISE_SENTINEL in str(value) for row in rows for value in tuple(row)):
        sqli_flag = get_flag(flags.SQLI_EXERCISE, g.participant_id)
    return render_template("admin_alarms.html", alarms=rows, query=query, sqli_flag=sqli_flag)


@bp.route("/users")
@login_required(role="admin")
def users():
    db = get_db()
    rows = db.execute(
        "SELECT id, email, name, role, created_at FROM users WHERE role IN ('customer','admin') ORDER BY id"
    ).fetchall()
    return render_template("admin_users.html", users=rows)


@bp.route("/tickets")
@login_required(role="admin")
def tickets():
    db = get_db()
    rows = db.execute(
        "SELECT tickets.*, users.name AS customer_name, users.email AS customer_email "
        "FROM tickets JOIN users ON users.id = tickets.user_id "
        "ORDER BY tickets.created_at DESC"
    ).fetchall()
    newest_submitter = rows[0]["participant_id"] if rows else None
    sxss_meta_flag = (
        get_flag(flags.SXSS_EXERCISE, newest_submitter)
        if newest_submitter and not hardening.is_hardened(flags.SXSS_EXERCISE)
        else None
    )
    return render_template("admin_tickets.html", tickets=rows, sxss_meta_flag=sxss_meta_flag)


@bp.route("/diagnostics", methods=["GET", "POST"])
def diagnostics():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            if hardening.is_hardened(flags.CMDINJECT_EXERCISE):
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", host],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout + result.stderr
            else:
                result = subprocess.run(
                    f"ping -c 1 -W 2 {host}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout + result.stderr
                if any(sep in host for sep in (";", "&&", "|", "\n", "`", "$(")):
                    output += f"\n\n# security misconfiguration exercise instance: {get_flag(flags.CMDINJECT_EXERCISE, g.participant_id)}"
        except subprocess.TimeoutExpired:
            output = "(timed out)"
        except FileNotFoundError:
            output = "(ping is not available on this host)"
    return render_template("admin_diagnostics.html", output=output, host=host)
