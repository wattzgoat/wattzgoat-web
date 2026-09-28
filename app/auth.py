import base64
import hashlib
import itertools
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from functools import wraps

from flask import Blueprint, g, redirect, render_template, request, url_for
from markupsafe import escape

from . import flags
from . import hardening
from .db import get_db
from .personalize import get_flag

bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# WattzGOAT rolls its own session handling ON PURPOSE. Flask's default cookie
# session is HMAC-signed and not guessable, which would rule out the
# "predictable session ID" teach instance entirely (this is the exact gap
# Juice Shop's JWT-everywhere auth left us with). Do not "fix" this by
# swapping in flask.session -- ask before changing it.
# ---------------------------------------------------------------------------
_session_counter = itertools.count(100000)


def issue_session_token() -> str:
    # Phase 6: SESSIONID_TEACH's hardened branch issues a real,
    # cryptographically random token instead of the next value in a
    # sequential counter -- the actual fix, not a stub. Note this makes
    # the flag structurally unreachable in hardened mode: there's no
    # sequence left to walk, and the dedicated account
    # (SESSIONID_ACCOUNT_EMAIL, see app/flags.py) never gets a
    # guessable token to land on.
    if hardening.is_hardened(flags.SESSIONID_TEACH):
        return secrets.token_hex(24)
    return str(next(_session_counter))


def weak_hash(password: str) -> str:
    """Deliberately weak, unsalted hash -- part of the lab, not a bug."""
    return hashlib.md5(password.encode()).hexdigest()


def is_weak_password(password: str) -> bool:
    """Shared weak-password policy check -- used by both signup
    (WEAKPW_TEACH) and account password changes (WEAKPW_CHANGE), so the
    two stay in sync rather than drifting apart as separate copies.

    Flags a password as weak if ANY of:
    - under 7 characters
    - entirely alphabetic (no digits, no symbols)
    - entirely numeric (no letters, no symbols)
    - alphanumeric (letters + digits, no symbols) but single-case --
      no mix of upper and lower case anywhere
    """
    if len(password) < 7:
        return True
    if password.isalpha():
        return True
    if password.isdigit():
        return True
    if password.isalnum():
        letters = [c for c in password if c.isalpha()]
        if letters and (all(c.islower() for c in letters) or all(c.isupper() for c in letters)):
            return True
    return False


def init_counters(db_path: str) -> None:
    """Resume the session counter from the DB's existing high-water mark.
    Without this, a container restart resets it to its starting value
    while old session rows with those same tokens are still sitting in
    the DB -- the very next login would crash on a primary-key collision.
    Doesn't make the tokens any less predictable, it just keeps the app
    from breaking the first time someone restarts the lab."""
    global _session_counter
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT token FROM sessions").fetchall()
        # Phase 6: a hardened-mode token (secrets.token_hex()) isn't a
        # base-10 integer, so it can't feed the sequential counter's
        # high-water mark -- skip those rather than letting one crash
        # this whole function (which would otherwise take the container
        # down on next boot if SESSIONID_TEACH was ever toggled hardened
        # before a restart, since some session rows would carry
        # non-numeric tokens).
        numeric_tokens = []
        for (t,) in rows:
            try:
                numeric_tokens.append(int(t))
            except (TypeError, ValueError):
                continue
        highest = max(numeric_tokens, default=99999)
        _session_counter = itertools.count(max(100000, highest + 1))
    except sqlite3.OperationalError:
        pass  # table doesn't exist yet (fresh DB) -- default start stands
    conn.close()


# ---------------------------------------------------------------------------
# Password-reset tokens are base64 of "<email>:<issued-at unix timestamp>".
# Fully stateless -- decode it, check the email exists, done, nothing to
# store or clean up. The timestamp LOOKS like it should matter (why else
# would it be in a field seemingly there for that purpose?) but nothing
# ever reads it back out to reject an old link. Base64 is an encoding, not
# encryption: decode one in CyberChef and both the target email and the
# fact that "expiry" is decorative are immediately obvious. Broken
# authentication exercise instance -- flagged below once a stale token is
# actually used successfully.
# ---------------------------------------------------------------------------
def make_reset_token(email: str) -> str:
    payload = f"{email}:{int(time.time())}"
    return base64.urlsafe_b64encode(payload.encode()).decode()


def decode_reset_token(token: str):
    """Returns (email, issued_at_unix) or (None, None) if it doesn't even
    parse. issued_at is never used to reject anything -- only to display
    and, on successful use, to decide whether it was already "stale"."""
    try:
        payload = base64.urlsafe_b64decode(token.encode()).decode()
        email, sep, ts = payload.rpartition(":")
        return (email, int(ts)) if sep else (None, None)
    except Exception:
        return None, None


def current_user():
    token = request.cookies.get("wgs_session")
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT users.*, sessions.logged_out_at AS session_logged_out_at FROM sessions "
        "JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token = ?",
        (token,),
    ).fetchone()
    # Phase 6: SESSIONREUSE_BONUS's hardened branch -- a session already
    # marked logged-out is treated as if it doesn't exist at all, rather
    # than the row being returned as a valid session regardless. This is
    # the actual server-side invalidation logout() never did (see
    # logout() below); the flag becomes unreachable once this is on,
    # since a replayed post-logout token now just looks logged-out.
    if row is not None and row["session_logged_out_at"] and hardening.is_hardened(flags.SESSIONREUSE_BONUS):
        return None
    return row


@bp.before_app_request
def load_user():
    g.user = current_user()
    g.session_reused = bool(g.user is not None and g.user["session_logged_out_at"])


@bp.after_app_request
def flag_session_reuse(resp):
    # A token that was already logged out is accepted anyway (see logout()
    # below) -- broken authentication bonus instance. Delivered as a
    # non-HttpOnly cookie, same as the XSS flags.
    if g.get("session_reused"):
        resp.set_cookie("flag_session_reuse", get_flag(flags.SESSIONREUSE_BONUS, g.participant_id))
    return resp


@bp.after_app_request
def flag_missing_hsts(resp):
    # Missing security headers exercise instance. Relocated off the login
    # page's own HTML (a comment merely describing a missing header was a
    # mismatch -- this puts the flag in the actual artifact, the response
    # headers themselves) onto a small custom header sent alongside every
    # /login response. Real HSTS is still genuinely absent app-wide; this
    # header doesn't pretend to be HSTS, it's just where the flag rides.
    #
    # Phase 6: hardened branch adds the actual missing headers instead of
    # just withholding the flag -- X-Content-Type-Options plus a real
    # Strict-Transport-Security, matching the remediation note in
    # flags.py word for word ("Add HSTS, X-Content-Type-Options, and a
    # real Content-Security-Policy app-wide").
    if request.path == "/login":
        if hardening.is_hardened(flags.HEADERS_EXERCISE):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
        else:
            resp.headers["X-Lab-Flag"] = get_flag(flags.HEADERS_EXERCISE, g.participant_id)
    return resp


def login_required(role: str | None = None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login"))
            if role and g.user["role"] != role:
                return redirect(url_for("auth.login"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email", "")
    password = request.form.get("password", "")
    name = request.form.get("name", "")

    # Phase 7: plain usability check, independent of hardening state (a
    # mismatched confirmation field is a data-entry error, not a security
    # control) -- checked server-side so it can't be skipped by disabling
    # JS, consistent with how every other check in this app works.
    #
    # NOTE: .get(..) with no default, not .get(.., "") -- a request that
    # omits the field ENTIRELY (every pre-existing API-style caller: the
    # test suite, curl, any script) is treated as "no confirmation was
    # asked for" and skips this check, rather than being treated as an
    # empty-string mismatch against a non-empty password. The real HTML
    # form always sends both fields (see signup.html's `required` inputs),
    # so this only relaxes the check for callers that were never filling
    # out that field in the first place -- it doesn't weaken what a real
    # signup through the browser enforces.
    confirm_password = request.form.get("confirm_password")
    if confirm_password is not None and password != confirm_password:
        return render_template("signup.html", error="Passwords don't match.")

    # NOTE: no length/complexity check on purpose -- "weak passwords" teach
    # instance.
    #
    # Phase 6: hardened branch rejects the signup outright and re-renders
    # the form with an error, reusing the exact same is_weak_password()
    # policy WEAKPW_CHANGE already enforces on the password-change form
    # (see customer.py:change_password()) rather than inventing a second,
    # possibly-inconsistent rule -- one real policy, applied everywhere
    # it should have been applied all along.
    if hardening.is_hardened(flags.WEAKPW_TEACH) and is_weak_password(password):
        return render_template(
            "signup.html",
            error="Password is too weak -- use at least 7 characters, mixing case, letters, and numbers.",
        )

    db = get_db()
    db.execute(
        "INSERT INTO users (email, password_hash, role, name) VALUES (?, ?, 'customer', ?)",
        (email, weak_hash(password), name),
    )
    db.commit()

    if is_weak_password(password) and not hardening.is_hardened(flags.WEAKPW_TEACH):
        return render_template("signup.html", weak_password_flag=get_flag(flags.WEAKPW_TEACH, g.participant_id))
    return redirect(url_for("auth.login"))


# In-memory only -- resets on restart, which is fine, this is just what
# proves the login and forgot-password endpoints never throttle no matter
# how many times you hit them in a running instance.
_login_attempts = defaultdict(int)
_reset_attempts = defaultdict(int)
RATE_LIMIT_THRESHOLD = 5


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        notice = "Lab reset to its seeded state." if request.args.get("reset") else None
        return render_template("login.html", notice=notice, plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id))

    email = request.form.get("email", "")
    password = request.form.get("password", "")
    db = get_db()

    # Phase 6: RATELIMIT_TEACH's hardened branch actually locks the
    # account out once the threshold is hit, instead of merely no longer
    # withholding the flag -- checked BEFORE looking up credentials at
    # all, so a correct password doesn't slip through mid-lockout either.
    if hardening.is_hardened(flags.RATELIMIT_TEACH) and _login_attempts.get(email, 0) >= RATE_LIMIT_THRESHOLD:
        return render_template(
            "login.html",
            error="Too many failed attempts. Try again later.",
            plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id),
        ), 429

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    # NOTE: two distinct messages on purpose -- "improper error handling"
    # exercise instance (username enumeration).
    if user is None or user["password_hash"] != weak_hash(password):
        _login_attempts[email] += 1
        # NOTE: no lockout at any attempt count -- lack of rate limiting
        # teach instance.
        ratelimit_flag = (
            get_flag(flags.RATELIMIT_TEACH, g.participant_id)
            if _login_attempts[email] >= RATE_LIMIT_THRESHOLD and not hardening.is_hardened(flags.RATELIMIT_TEACH)
            else None
        )
        error = "Invalid username" if user is None else "Invalid password"
        return render_template(
            "login.html",
            error=error,
            errhandling_flag=get_flag(flags.ERRHANDLING_EXERCISE, g.participant_id),
            ratelimit_flag=ratelimit_flag,
            plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id),
        ), 401

    _login_attempts.pop(email, None)
    token = issue_session_token()
    db.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user["id"]))
    # Footer "Last logged in" shows the previous login, so rotate the old
    # value across before stamping this one. Only this form login writes
    # these columns -- planted/replayed session cookies never do.
    db.execute(
        "UPDATE users SET previous_login_at = last_login_at, last_login_at = datetime('now') WHERE id = ?",
        (user["id"],),
    )
    db.commit()

    dest = "admin.dashboard" if user["role"] == "admin" else "customer.dashboard"
    resp = redirect(url_for(dest))
    resp.set_cookie("wgs_session", token, httponly=True)

    # NOTE: this one is set as an ordinary (non-HttpOnly) cookie on
    # purpose -- a working reflected-XSS payload can read it via
    # document.cookie. Stored XSS's two flags do NOT live here (see
    # dashboard.html / admin_tickets.html) -- if they did, exploiting the
    # reflected instance on /usage would incidentally hand over both
    # stored-XSS flags too, without ever touching either vulnerable page.
    if user["role"] == "customer":
        resp.set_cookie("flag_reflected_xss", get_flag(flags.RXSS_TEACH, g.participant_id))

    return resp


@bp.route("/logout", methods=["POST"])
def logout():
    # NOTE: logout only stamps logged_out_at and clears the browser cookie.
    # current_user() never checks that column, so a captured token keeps
    # working after logout, and there's no expiry either -- session
    # invalidation flaw, broken authentication bonus instance.
    token = request.cookies.get("wgs_session")
    if token:
        db = get_db()
        db.execute("UPDATE sessions SET logged_out_at = datetime('now') WHERE token = ?", (token,))
        db.commit()
    resp = redirect(url_for("auth.login"))
    resp.delete_cookie("wgs_session")
    return resp


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "")
    db = get_db()

    # Phase 6: RATELIMIT_EXERCISE's hardened branch, same real-lockout
    # shape as RATELIMIT_TEACH on /login above -- checked before doing
    # any work for this request, so a locked-out email doesn't even get
    # a fresh reset email queued.
    if hardening.is_hardened(flags.RATELIMIT_EXERCISE) and _reset_attempts.get(email, 0) >= RATE_LIMIT_THRESHOLD:
        return render_template("forgot_password.html", ratelimit_error=True), 429

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    _reset_attempts[email] += 1
    ratelimit_flag = (
        get_flag(flags.RATELIMIT_EXERCISE, g.participant_id)
        if _reset_attempts[email] >= RATE_LIMIT_THRESHOLD and not hardening.is_hardened(flags.RATELIMIT_EXERCISE)
        else None
    )

    if user is None:
        # Confirms account existence AND echoes the raw email back
        # unescaped -- reflected XSS exercise instance. Delivered via this
        # page's <title> (not a cookie) -- a working payload here is
        # `alert(document.title)`, not `alert(document.cookie)`. Moved off
        # cookies for the same reason stored XSS was: a cookie-delivered
        # flag is readable from ANY XSS anywhere in the session, not just
        # this specific injection point, which let one working payload
        # hand over flags that had nothing to do with where it fired.
        #
        # Phase 6: RXSS_EXERCISE's hardened branch escapes the echoed
        # email before it reaches the template, same pattern as
        # RXSS_TEACH on /usage (see customer.py).
        return render_template(
            "forgot_password.html",
            not_found_email=escape(email) if hardening.is_hardened(flags.RXSS_EXERCISE) else email,
            ratelimit_flag=ratelimit_flag,
            rxss_title_flag=get_flag(flags.RXSS_EXERCISE, g.participant_id),
        )

    token = make_reset_token(email)
    reset_link = url_for("auth.reset_password", token=token, _external=True)
    body_html = render_template("email_reset_password.html", name=user["name"], reset_link=reset_link)
    db.execute(
        "INSERT INTO emails (recipient_email, subject, body_html) VALUES (?, ?, ?)",
        (email, "Reset your WattzGOAT password", body_html),
    )
    db.commit()
    return render_template("forgot_password.html", sent=True, ratelimit_flag=ratelimit_flag)


@bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.values.get("token", "")
    email, issued_at = decode_reset_token(token)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone() if email else None

    if user is None:
        return render_template("reset_password.html", error="Invalid or expired link"), 400

    if request.method == "GET":
        issued_display = datetime.fromtimestamp(issued_at).strftime("%b %d, %Y %I:%M %p") if issued_at else None
        return render_template("reset_password.html", token=token, email=email, issued_at=issued_display)

    new_password = request.form.get("password", "")

    # NOTE: an hour-old (or decades-old) token resets the password just
    # fine -- the timestamp embedded in it is never checked. Broken
    # authentication exercise instance.
    is_stale = issued_at is not None and (time.time() - issued_at) > 3600

    # Phase 6: hardened branch actually rejects a stale token BEFORE
    # applying the update, instead of applying it unconditionally and
    # only noting the staleness afterward -- the real fix. A token with
    # no timestamp at all (issued_at is None, i.e. it never parsed as
    # "email:timestamp") is left alone here since that's decode_reset_
    # token()'s own concern, not this one.
    if is_stale and hardening.is_hardened(flags.OLDTOKEN_EXERCISE):
        return render_template("reset_password.html", error="This reset link has expired. Please request a new one."), 400

    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak_hash(new_password), user["id"]))
    db.commit()

    if is_stale:
        return render_template("reset_password_done.html", oldtoken_flag=get_flag(flags.OLDTOKEN_EXERCISE, g.participant_id))
    return redirect(url_for("auth.login"))
