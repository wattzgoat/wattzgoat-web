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

_session_counter = itertools.count(100000)


def issue_session_token() -> str:
    if hardening.is_hardened(flags.SESSIONID_TEACH):
        return secrets.token_hex(24)
    return str(next(_session_counter))


def weak_hash(password: str) -> str:
    """Unsalted password hash."""
    return hashlib.md5(password.encode()).hexdigest()


def is_weak_password(password: str) -> bool:
    """True if a password fails the strength policy (length and a mix of letters, case and numbers)."""
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
    """Resume the session counter from the highest token already in the database."""
    global _session_counter
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT token FROM sessions").fetchall()
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
    if row is not None and row["session_logged_out_at"] and hardening.is_hardened(flags.SESSIONREUSE_BONUS):
        return None
    return row


@bp.before_app_request
def load_user():
    g.user = current_user()
    g.session_reused = bool(g.user is not None and g.user["session_logged_out_at"])


@bp.after_app_request
def flag_session_reuse(resp):
    if g.get("session_reused"):
        resp.set_cookie("flag_session_reuse", get_flag(flags.SESSIONREUSE_BONUS, g.participant_id))
    return resp


@bp.after_app_request
def flag_missing_hsts(resp):
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

    confirm_password = request.form.get("confirm_password")
    if confirm_password is not None and password != confirm_password:
        return render_template("signup.html", error="Passwords don't match.")

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


_login_attempts = defaultdict(int)
_reset_attempts = defaultdict(int)
RATE_LIMIT_THRESHOLD = 5

_forged_reset_pending: dict = {}


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        notice = "Lab reset to its seeded state." if request.args.get("reset") else None
        return render_template("login.html", notice=notice, plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id))

    email = request.form.get("email", "")
    password = request.form.get("password", "")
    db = get_db()

    if hardening.is_hardened(flags.RATELIMIT_TEACH) and _login_attempts.get(email, 0) >= RATE_LIMIT_THRESHOLD:
        return render_template(
            "login.html",
            error="Too many failed attempts. Try again later.",
            plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id),
        ), 429

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None or user["password_hash"] != weak_hash(password):
        _login_attempts[email] += 1
        ratelimit_flag = (
            get_flag(flags.RATELIMIT_TEACH, g.participant_id)
            if _login_attempts[email] >= RATE_LIMIT_THRESHOLD and not hardening.is_hardened(flags.RATELIMIT_TEACH)
            else None
        )
        error = "Invalid username" if user is None else "Invalid password"
        already_redeemed = db.execute(
            "SELECT 1 FROM flag_redemptions WHERE flag_key = ? AND participant_id = ?",
            (flags.ERRHANDLING_EXERCISE, g.participant_id),
        ).fetchone()
        return render_template(
            "login.html",
            error=error,
            errhandling_flag=None if already_redeemed else get_flag(flags.ERRHANDLING_EXERCISE, g.participant_id),
            ratelimit_flag=ratelimit_flag,
            plaintext_flag=get_flag(flags.PLAINTEXT_TEACH, g.participant_id),
        ), 401

    _login_attempts.pop(email, None)
    token = issue_session_token()
    db.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user["id"]))
    db.execute(
        "UPDATE users SET previous_login_at = last_login_at, last_login_at = datetime('now') WHERE id = ?",
        (user["id"],),
    )
    db.commit()

    dest = "admin.dashboard" if user["role"] == "admin" else "customer.dashboard"
    resp = redirect(url_for(dest))
    if request.is_secure:
        resp.set_cookie("wgs_session", token, httponly=True, samesite="None", secure=True)
    else:
        resp.set_cookie("wgs_session", token, httponly=True)

    if user["role"] == "customer":
        resp.set_cookie("flag_reflected_xss", get_flag(flags.RXSS_TEACH, g.participant_id))

    return resp


@bp.route("/logout", methods=["POST"])
def logout():
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

    is_stale = issued_at is not None and (time.time() - issued_at) > 3600

    if is_stale and hardening.is_hardened(flags.OLDTOKEN_EXERCISE):
        return render_template("reset_password.html", error="This reset link has expired. Please request a new one."), 400

    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak_hash(new_password), user["id"]))
    db.commit()

    _forged_reset_pending[user["id"]] = g.participant_id
    return render_template("reset_password_done.html")
