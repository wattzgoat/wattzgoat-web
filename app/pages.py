from flask import Blueprint, render_template

bp = Blueprint("pages", __name__)

# Plain, unauthenticated content pages. Written in-universe as flavor for
# the fictional "WattzGOAT Smart Meter" product line, in the same running-
# gag spirit as Juice Shop's own Terms of Use -- not meant to be taken
# seriously, and deliberately separate from the real, serious safety
# disclaimer (see base.html), which is not a joke.


@bp.route("/terms")
def terms():
    return render_template("terms.html")


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


@bp.route("/contact")
def contact():
    return render_template("contact.html")
