import os
import subprocess

from flask import Blueprint, g, redirect, render_template, request, url_for

from .auth import login_required, weak_hash
from .db import get_db
from .personalize import get_flag
from . import flags

bp = Blueprint("admin", __name__, url_prefix="/admin")

# Intended firmware storage: FIRMWARE_DIR/<meter_code>/<filename>. canary.txt
# sits one level up, directly inside FIRMWARE_DIR -- reachable via exactly
# "../canary.txt" from within any meter's own subfolder, mirroring the
# bill-download traversal's simplicity (MTR-1004/../MTR-1002/...). It's a
# small, dedicated, harmless target purpose-built for this exercise, not a
# real app file -- so a participant's traversal has a real, visible,
# non-destructive thing to prove impact against (see admin.firmware_canary
# below), rather than something that could break the rest of the app for
# everyone on a shared instance.
FIRMWARE_DIR = os.path.join(os.path.dirname(__file__), "firmware")
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
    # NOTE: there's no "change password" flow anywhere in this app for
    # admin accounts -- the seeded default is the only password they'll
    # ever have. Weak passwords exercise instance.
    weakpw_flag = get_flag(flags.WEAKPW_EXERCISE, g.participant_id) if g.user["password_hash"] == weak_hash("changeme") else None
    # Sensitive information disclosure teach instance: this account's own
    # dashboard confirms whoever's here followed the credential leaked on
    # the login page to somewhere real.
    devadmin_flag = get_flag(flags.DEVADMIN_LEAK, g.participant_id) if g.user["email"] == flags.DEVADMIN_ACCOUNT_EMAIL else None
    return render_template(
        "admin_dashboard.html", user=g.user, stats=stats, weakpw_flag=weakpw_flag, devadmin_flag=devadmin_flag
    )


@bp.route("/meters")
@login_required(role="admin")
def meters():
    query = request.args.get("q", "")
    db = get_db()
    # NOTE: raw string interpolation into the query -- SQL injection teach
    # instance. A UNION SELECT against `meters` (the table this query
    # already reads) is enough to pull in a row ordinary browsing would
    # otherwise exclude. The `AND users.role != 'service'` lives in the
    # JOIN condition, not the WHERE clause, specifically so a UNION's
    # trailing `--` (which only truncates the WHERE clause) doesn't need
    # to account for it -- the exact same technique as before still works.
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

    # Insecure file upload teach instance: no restriction at all on file
    # type, extension, or size -- whatever gets sent, gets saved.
    #
    # Insecure file upload exercise instance: the save path is built
    # directly from the client-supplied filename (uploaded.filename),
    # completely unsanitized -- no secure_filename()-style cleanup, no
    # check that the resolved path stays inside the intended per-meter
    # folder. A filename like "../canary.txt" walks the save location
    # right out of that folder.
    save_path = os.path.normpath(os.path.join(FIRMWARE_DIR, meter["meter_code"], uploaded.filename))
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    uploaded.save(save_path)

    fileupload_flag = None
    intended_dir = os.path.normpath(os.path.join(FIRMWARE_DIR, meter["meter_code"]))
    if save_path == CANARY_PATH:
        fileupload_flag = get_flag(flags.FILEUPLOAD_EXERCISE, g.participant_id)
    elif os.path.dirname(save_path) == intended_dir:
        fileupload_flag = get_flag(flags.FILEUPLOAD_TEACH, g.participant_id)

    return render_template("firmware_uploaded.html", meter_code=meter["meter_code"], filename=uploaded.filename, flag=fileupload_flag)


@bp.route("/firmware-canary")
@login_required(role="admin")
def firmware_canary():
    # Visible proof the traversal write actually landed somewhere real --
    # a small, dedicated, harmless target (see FIRMWARE_DIR/CANARY_PATH
    # above), not a live app file that overwriting would actually break
    # for other people on a shared instance.
    try:
        with open(CANARY_PATH, "r", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        content = "(untouched -- nothing has overwritten this file yet)"
    return render_template("firmware_canary.html", content=content)


@bp.route("/meters/<int:meter_id>/disconnect", methods=["POST"])
@login_required()
def disconnect_meter(meter_id):
    # NOTE: login_required() with no role= -- ANY logged-in customer can
    # call this directly for a meter that isn't theirs, not just admins.
    # Broken authentication / privilege escalation teach instance. This is
    # the flagship impact chain: a customer flips a stranger's power off,
    # visible live on that stranger's own dashboard.
    db = get_db()
    meter = db.execute("SELECT user_id FROM meters WHERE id = ?", (meter_id,)).fetchone()
    is_escalation = meter is not None and g.user["role"] != "admin" and meter["user_id"] != g.user["id"]

    db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter_id,))
    db.commit()

    if is_escalation:
        return render_template("privesc_done.html", action="disconnected", flag=get_flag(flags.PRIVESC_TEACH, g.participant_id))
    return redirect(request.referrer or url_for("admin.meters"))


@bp.route("/meters/<int:meter_id>/reconnect", methods=["POST"])
@login_required()
def reconnect_meter(meter_id):
    # Same missing role check as disconnect above.
    db = get_db()
    meter = db.execute("SELECT user_id FROM meters WHERE id = ?", (meter_id,)).fetchone()
    is_escalation = meter is not None and g.user["role"] != "admin" and meter["user_id"] != g.user["id"]

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
    # NOTE: same raw-interpolation pattern as the meters search above --
    # SQL injection exercise instance, different page, same technique, and
    # a UNION here targets `alarms` (what this query reads) rather than
    # `meters`, which is why the two pages' flags don't show up together.
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
    # Stored XSS exercise instance: personalized to whoever submitted the
    # most recent ticket, not to whoever's currently viewing as admin --
    # same reasoning as SXSS_TEACH's nickname_set_by (see
    # customer.py:dashboard()). rows[0] is the newest ticket given the
    # ORDER BY above; participant_id is NULL for anything not created
    # through the normal /support flow.
    newest_submitter = rows[0]["participant_id"] if rows else None
    sxss_meta_flag = get_flag(flags.SXSS_EXERCISE, newest_submitter) if newest_submitter else None
    return render_template("admin_tickets.html", tickets=rows, sxss_meta_flag=sxss_meta_flag)


@bp.route("/diagnostics", methods=["GET", "POST"])
def diagnostics():
    # NOTE: no @login_required at all -- an internal tool nobody got
    # around to locking down, sitting at an admin-sounding path that
    # implies protection it doesn't have. Security misconfiguration
    # exercise instance.
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # NOTE: shells out with the raw input -- OS command injection.
        try:
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
    return render_template("admin_diagnostics.html", output=output, host=host)
