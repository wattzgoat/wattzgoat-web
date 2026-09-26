import subprocess

from flask import Blueprint, g, redirect, render_template, request, url_for

from .auth import login_required, weak_hash
from .db import get_db
from . import flags

bp = Blueprint("admin", __name__, url_prefix="/admin")


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
    weakpw_flag = flags.WEAKPW_EXERCISE if g.user["password_hash"] == weak_hash("changeme") else None
    # Sensitive information disclosure teach instance: this account's own
    # dashboard confirms whoever's here followed the credential leaked on
    # the login page to somewhere real.
    devadmin_flag = flags.DEVADMIN_LEAK if g.user["email"] == flags.DEVADMIN_ACCOUNT_EMAIL else None
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
    return render_template("admin_meters.html", meters=rows, query=query)


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
        return render_template("privesc_done.html", action="disconnected", flag=flags.PRIVESC_TEACH)
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
        return render_template("privesc_done.html", action="reconnected", flag=flags.PRIVESC_TEACH)
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
    return render_template("admin_alarms.html", alarms=rows, query=query)


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
    return render_template("admin_tickets.html", tickets=rows, sxss_meta_flag=flags.SXSS_EXERCISE)


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
                output += f"\n\n# security misconfiguration exercise instance: {flags.CMDINJECT_EXERCISE}"
        except subprocess.TimeoutExpired:
            output = "(timed out)"
    return render_template("admin_diagnostics.html", output=output, host=host)
