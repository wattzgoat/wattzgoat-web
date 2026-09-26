from flask import Blueprint, redirect, render_template, request, url_for

from .db import get_db

bp = Blueprint("mail", __name__, url_prefix="/mail")


def _current_mailbox():
    return request.cookies.get("mail_session")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("mail_login.html")

    email = request.form.get("email", "")
    # NOTE: password is accepted by the form but never checked against
    # anything -- "logging in" here is really just naming a mailbox to
    # view. Broken authentication exercise instance, independent of the
    # reset token's own weakness. Expected behavior, no flag attached.
    request.form.get("password", "")

    resp = redirect(url_for("mail.inbox"))
    resp.set_cookie("mail_session", email, httponly=True)
    return resp


@bp.route("/logout", methods=["POST"])
def logout():
    resp = redirect(url_for("mail.login"))
    resp.delete_cookie("mail_session")
    return resp


@bp.route("/")
def inbox():
    mailbox = _current_mailbox()
    if not mailbox:
        return redirect(url_for("mail.login"))

    db = get_db()
    emails = db.execute(
        "SELECT * FROM emails WHERE recipient_email = ? ORDER BY id DESC",
        (mailbox,),
    ).fetchall()
    return render_template("mail_inbox.html", mailbox=mailbox, emails=emails)


@bp.route("/<int:email_id>")
def view_email(email_id):
    mailbox = _current_mailbox()
    if not mailbox:
        return redirect(url_for("mail.login"))

    db = get_db()
    email = db.execute(
        "SELECT * FROM emails WHERE id = ? AND recipient_email = ?",
        (email_id, mailbox),
    ).fetchone()
    if email is None:
        return redirect(url_for("mail.inbox"))
    return render_template("mail_detail.html", mailbox=mailbox, email=email)
