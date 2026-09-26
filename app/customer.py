import io
import os
import sqlite3
import traceback

from flask import Blueprint, abort, g, make_response, redirect, render_template, request, send_file, url_for

from .auth import login_required, weak_hash
from .db import get_db, mysql_style_error
from .devices import issue_device_token
from .personalize import get_flag
from . import billing
from . import flags

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
    # NOTE: rendered into the page for the "Sync now" button to use --
    # that's what puts a real device JWT in front of the browser's proxy
    # (Burp) with zero special setup, same as the reasoning behind sharing
    # /api/telemetry between the simulators and this button in the first
    # place.
    device_tokens = {m["id"]: issue_device_token(m["meter_code"]) for m in meters}

    # NOTE: this specific account is never logged into directly -- it's
    # reached only by guessing/walking a sequential wgs_session value
    # (insecure cryptography teach instance). Whoever's session resolves
    # to this account, however they got here, sees the flag -- that's the
    # whole exercise, and matches how every other flag in this app is
    # delivered to whatever session happens to trigger it.
    sessionid_flag = get_flag(flags.SESSIONID_TEACH, g.participant_id) if g.user["email"] == flags.SESSIONID_ACCOUNT_EMAIL else None

    # Stored XSS teach instance: the flag is personalized to whoever
    # actually set the exploited nickname (nickname_set_by), not to
    # whoever's currently viewing the dashboard -- multiple participants
    # can share a seeded customer account, and the nickname itself stays
    # genuinely shared state once set, but a later viewer shouldn't get
    # credit for someone else's earlier work just by loading the page.
    nickname_setter = next((m["nickname_set_by"] for m in meters if m["nickname_set_by"]), None)
    sxss_title_flag = get_flag(flags.SXSS_TEACH, nickname_setter) if nickname_setter else None

    resp = make_response(render_template(
        "dashboard.html", user=g.user, meters=meters, device_tokens=device_tokens,
        sessionid_flag=sessionid_flag, sxss_title_flag=sxss_title_flag,
    ))
    # NOTE: no X-Frame-Options / CSP frame-ancestors on this response --
    # the Recharge link on this page is embeddable in an invisible iframe
    # on another site. Missing security headers teach instance, delivered
    # via a response header (matching the exercise instance on /login)
    # rather than a page comment.
    resp.headers["X-Lab-Flag"] = get_flag(flags.HEADERS_TEACH, g.participant_id)
    return resp


@bp.route("/meters/<int:meter_id>/nickname", methods=["POST"])
@login_required(role="customer")
def update_nickname(meter_id):
    # Ownership IS checked here -- this route isn't the access-control
    # exercise. The bug on this page is purely in how the nickname gets
    # rendered back out (see dashboard.html) -- stored XSS teach instance.
    nickname = request.form.get("nickname", "")
    db = get_db()
    db.execute(
        "UPDATE meters SET nickname = ?, nickname_set_by = ? WHERE id = ? AND user_id = ?",
        (nickname, g.participant_id, meter_id, g.user["id"]),
    )
    db.commit()

    resp = make_response(redirect(url_for("customer.dashboard")))
    if _is_cross_origin(request):
        # CSRF exercise instance: same missing-token gap as the password
        # form, on a lower-stakes action -- this route redirects rather
        # than rendering a page, so the flag rides on a response header
        # instead of visible page text, same technique as the missing-
        # headers category's own header-delivered flags. Needs Burp/
        # devtools to see, which is realistic: a CSRF PoC is usually
        # confirmed by inspecting the actual request/response, not by
        # eyeballing the page the victim's browser lands on.
        resp.headers["X-Lab-Flag"] = get_flag(flags.CSRF_EXERCISE, g.participant_id)
    return resp


def _is_cross_origin(req) -> bool:
    # CSRF detection, not blocking -- keeps these routes exploitable while
    # letting the app recognize how they were exploited. A legitimate
    # in-app form submission carries an Origin header matching this app's
    # own origin (modern browsers send Origin on same-origin POSTs too,
    # not just cross-origin). A hosted attacker page -- or a local
    # file:// PoC, which gets Origin: null and no Referer at all -- won't
    # match. This is a real, standard CSRF defense technique (Origin/
    # Referer checking), used here for detection instead of prevention.
    own_origin = req.host_url.rstrip("/")
    origin = req.headers.get("Origin")
    if origin is not None:
        return origin != own_origin
    referer = req.headers.get("Referer")
    if referer is not None:
        return not referer.startswith(own_origin)
    # Neither header present at all -- most consistent with a file://
    # PoC page, where browsers suppress Referer entirely.
    return True


@bp.route("/account", methods=["GET"])
@login_required()
def account():
    # Saving profile fields happens client-side via PATCH /api/account
    # (app/api.py) -- that's where the mass-assignment bug lives. Open to
    # any logged-in role now, not just customers -- admins get the same
    # page (see base.html's nav) so the password-change flow below
    # applies uniformly to both.
    return render_template("account.html", user=g.user)


@bp.route("/account/password", methods=["POST"])
@login_required()
def change_password():
    # Broken authentication teach instance: no current-password field on
    # this form at all, for either role -- any active session, however it
    # was obtained, can fully take over the account by setting a new
    # password. Submitting this form at all demonstrates the missing
    # check; it doesn't require any special trickery to notice. See the
    # CSRF category for how this becomes a remote, no-session-needed
    # takeover, chained off this same gap.
    new_password = request.form.get("new_password", "")
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak_hash(new_password), g.user["id"]))
    db.commit()

    # Weak passwords instance: same missing length/complexity check as
    # signup, just on a different form.
    weakpw_flag = get_flag(flags.WEAKPW_CHANGE, g.participant_id) if len(new_password) < 4 else None
    pwchange_flag = get_flag(flags.PWCHANGE_TEACH, g.participant_id)
    # CSRF teach instance: no anti-CSRF token on this form at all, so a
    # forged cross-origin submission works just as well as a real one --
    # combined with the missing current-password check above, that's a
    # full remote account takeover from a hosted page or a local HTML
    # file, no session-riding trickery beyond a plain auto-submitting form.
    csrf_flag = get_flag(flags.CSRF_TEACH, g.participant_id) if _is_cross_origin(request) else None

    return render_template(
        "account.html", user=g.user, password_changed=True,
        weakpw_flag=weakpw_flag, pwchange_flag=pwchange_flag, csrf_flag=csrf_flag,
    )


@bp.route("/recharge", methods=["GET", "POST"])
@login_required(role="customer")
def recharge():
    if request.method == "GET":
        meter = _own_meters()[0] if _own_meters() else None
        return render_template("recharge.html", meter=meter)

    meters = _own_meters()
    if not meters:
        return redirect(url_for("customer.dashboard"))
    meter = meters[0]
    # NOTE: catches this one specific failure and renders the real
    # traceback straight to the page instead of a generic error --
    # improper error handling instance (recategorized from "sensitive
    # information disclosure" -- both amount to "the app reveals internals
    # when something goes wrong", which is what this category covers). A
    # developer's well-intentioned "let me show something useful here
    # while I'm debugging this" that never got removed.
    try:
        amount_paid = float(request.form.get("amount_paid", 0) or 0)
    except ValueError:
        tb = traceback.format_exc() + f"\n# improper error handling instance: {get_flag(flags.INFOLEAK_TEACH, g.participant_id)}"
        return render_template("error_debug.html", traceback=tb), 500

    # NOTE: if a units_credited value is present at all, it's trusted
    # outright instead of being recomputed from amount_paid -- business
    # logic teach instance. The rendered form never sends this field, so it
    # only shows up when someone crafts the request directly.
    raw_override = request.form.get("units_credited")
    units_credited = float(raw_override) if raw_override not in (None, "") else round(amount_paid / RECHARGE_RATE, 2)
    buslogic_flag = get_flag(flags.BUSLOGIC_TEACH, g.participant_id) if raw_override not in (None, "") else None

    db = get_db()
    db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (units_credited, meter["id"]))
    db.execute(
        "INSERT INTO recharges (user_id, amount_paid, units_credited) VALUES (?, ?, ?)",
        (g.user["id"], amount_paid, units_credited),
    )
    db.commit()
    meter = _own_meters()[0]
    return render_template("recharge.html", meter=meter, credited=units_credited, buslogic_flag=buslogic_flag)


@bp.route("/solar", methods=["GET", "POST"])
@login_required(role="customer")
def solar():
    if request.method == "GET":
        meter = _own_meters()[0] if _own_meters() else None
        return render_template("solar.html", meter=meter)

    meters = _own_meters()
    if not meters:
        return redirect(url_for("customer.dashboard"))
    meter = meters[0]
    # NOTE: no upper bound and nothing cross-checked against real usage --
    # business logic exercise instance: any claimed export is paid out at
    # face value.
    exported_kwh = float(request.form.get("exported_kwh", 0) or 0)
    credit_amount = round(exported_kwh * SOLAR_CREDIT_RATE, 2)
    # NOTE: 1000 kWh is roughly a whole year's residential solar export --
    # anything past that in one submission is well outside what's
    # physically plausible, and nothing here checks for it. Business logic
    # exercise instance.
    buslogic_flag = get_flag(flags.BUSLOGIC_EXERCISE, g.participant_id) if exported_kwh > 1000 else None

    db = get_db()
    db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (credit_amount, meter["id"]))
    db.execute(
        "INSERT INTO solar_exports (user_id, exported_kwh, credit_amount) VALUES (?, ?, ?)",
        (g.user["id"], exported_kwh, credit_amount),
    )
    db.commit()
    meter = _own_meters()[0]
    return render_template("solar.html", meter=meter, credited=credit_amount, buslogic_flag=buslogic_flag)


@bp.route("/usage", methods=["GET"])
@login_required(role="customer")
def usage():
    query = request.args.get("q", "")
    if not query:
        return render_template("usage.html", query=None, results=None, db_error=None)

    meter = _own_meters()[0] if _own_meters() else None
    meter_id = meter["id"] if meter else -1

    # NOTE: built with a raw f-string instead of a parameterized query on
    # purpose -- SQL injection isn't the primary point of THIS instance
    # (see app/admin.py for the two dedicated ones), but the same raw
    # interpolation makes this genuinely UNION-injectable too -- SQL
    # injection bonus third instance, no WHERE filtering needed since a
    # fake reading sits in `readings` alongside the real ones (see
    # scripts/seed.py). The other two side effects of this exact shape are
    # a stray quote breaking the query with the raw DB error reaching the
    # page (improper error handling teach instance), and the query text
    # echoed back unescaped in the "no results" message (reflected XSS
    # teach instance).
    sql = f"SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = {meter_id} AND recorded_at LIKE '%{query}%'"

    db = get_db()
    sqli_flag = None
    try:
        results = db.execute(sql).fetchall()
        db_error = None
        # SQLi bonus sentinel detection -- see app/flags.py's module
        # docstring for why this is a sentinel check rather than the flag
        # being the exfiltrated data itself. Scans every column of every
        # row rather than one specific column, since which SELECT
        # position the decoy row's sentinel lands in depends on the
        # exact UNION payload a participant wrote.
        if results and any(
            flags.SQLI_BONUS_SENTINEL in str(value) for row in results for value in tuple(row)
        ):
            sqli_flag = get_flag(flags.SQLI_BONUS, g.participant_id)
    except sqlite3.OperationalError as e:
        results = None
        db_error = mysql_style_error(e) + f"\n-- improper error handling: {get_flag(flags.ERRHANDLING_TEACH, g.participant_id)}"

    return render_template("usage.html", query=query, results=results, db_error=db_error, sqli_flag=sqli_flag)


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

    # NOTE: this view escapes subject/description normally (no |safe) --
    # the stored XSS instance is specifically on the admin's ticket view
    # (app/templates/admin_tickets.html), not here.
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
    # NOTE: path comes straight from the query string and gets joined
    # onto BILLS_DIR with no check that it stays inside it -- a legit
    # link here looks like ?path=MTR-1004/2026-09.pdf (this account's own
    # meter code), so ?path=../MTR-1002/2026-09.pdf walks up one level and
    # into another customer's folder instead. Security misconfiguration
    # teach instance (the flag is inside that specific PDF, not returned
    # by this route). Real path traversal, not just an ID swap -- the
    # requested meter code doesn't have to be one that exists anywhere in
    # this account's own data, and it isn't limited to one level either:
    # going up further reaches outside bills/ entirely. Below, resolving
    # to a directory lists it instead of 404ing, which is what actually
    # makes "walk up, then browse" a repeatable technique rather than
    # something that only happens to work at one specific depth.
    rel_path = request.args.get("path", "")
    full_path = os.path.normpath(os.path.join(BILLS_DIR, rel_path))

    if os.path.isdir(full_path):
        try:
            entries = sorted(os.listdir(full_path))
        except OSError:
            abort(404)
        parent = os.path.normpath(os.path.join(rel_path, ".."))
        return render_template("bill_directory_listing.html", rel_path=rel_path or ".", parent=parent, entries=entries)

    if not os.path.isfile(full_path):
        abort(404)

    # Ben Osei's bill (MTR-1002/<period>.pdf) is the one that carries the
    # TRAVERSAL_TEACH flag. It's regenerated here, in memory, with a flag
    # personalized to whoever's asking, rather than served from the
    # static placeholder scripts/generate_bills.py baked in at image
    # build time -- see app/billing.py for why. normpath'd comparison so
    # this still matches regardless of which traversal sequence a
    # participant used to reach it.
    ben_bill_path = os.path.normpath(os.path.join(BILLS_DIR, billing.BEN_METER_CODE, f"{billing.BILL_PERIOD}.pdf"))
    if full_path == ben_bill_path:
        pdf_bytes = billing.draw_ben_bill_pdf(get_flag(flags.TRAVERSAL_TEACH, g.participant_id))
        return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf", download_name=f"{billing.BILL_PERIOD}.pdf")

    return send_file(full_path, mimetype="application/pdf")
