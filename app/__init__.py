import os

from flask import Flask, Response, g, redirect, request, send_from_directory, url_for

from . import db as db_module
from . import flags as flags_module
from . import hardening


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "/app/data/app.db")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "wattzgoat-training-lab")

    db_module.init_app(app)

    # Phase 6: exposed so templates can branch on hardening state and
    # embed a real anti-CSRF token directly (see CSRF_TEACH/CSRF_EXERCISE
    # in customer.py + account.html/dashboard.html, SXSS_TEACH/
    # SXSS_EXERCISE in dashboard.html/admin_tickets.html, DEVADMIN_LEAK in
    # login.html, ASSISTANT_OUTPUT_XSS in _assistant_widget.html) without
    # every view function having to thread an extra flag through its own
    # render_template() call.
    app.jinja_env.globals["is_hardened"] = hardening.is_hardened
    app.jinja_env.globals["csrf_token"] = hardening.csrf_token

    from .auth import bp as auth_bp
    from .auth import init_counters
    from .customer import bp as customer_bp
    from .admin import bp as admin_bp
    from .api import bp as api_bp
    from .mail import bp as mail_bp
    from .progress import bp as progress_bp
    from .ops import bp as ops_bp
    from .assistant import bp as assistant_bp
    from .fieldtech import bp as fieldtech_bp
    from .leaderboard import bp as leaderboard_bp
    from .pages import bp as pages_bp
    from .personalize import bp as personalize_bp

    if os.path.exists(app.config["DB_PATH"]):
        init_counters(app.config["DB_PATH"])

    app.register_blueprint(auth_bp)
    app.register_blueprint(customer_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(mail_bp)
    app.register_blueprint(progress_bp)
    app.register_blueprint(ops_bp)
    app.register_blueprint(assistant_bp)
    app.register_blueprint(fieldtech_bp)
    app.register_blueprint(leaderboard_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(personalize_bp)

    @app.route("/")
    def index():
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["role"] == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("customer.dashboard"))

    # Phase 6: PLAINTEXT_TEACH and PLAINTEXT_EXERCISE's hardened
    # branches -- both entry points genuinely stop being reachable over
    # the plaintext port, rather than just withholding the flag while
    # still serving the request in the clear. Scoped to exactly the two
    # flagged paths (not every route on port 5001) so each flag's toggle
    # stays independent, matching the pattern everywhere else in this
    # app. code=308 (not 301/302) so /api/telemetry's POST body and
    # method survive the redirect -- a 301/302 would silently turn a
    # device's POST into a GET on most clients, which would look like
    # "the device stopped working" rather than "TLS is now required".
    # Hardcodes the internal port pair (5000 HTTPS / 5001 plaintext, see
    # run.py) rather than the external Portainer mapping, which varies
    # per instance and isn't what this process itself is listening on.
    @app.before_request
    def _plaintext_hardening_redirect():
        if request.environ.get("SERVER_PORT") != "5001":
            return None
        if request.path == "/login" and hardening.is_hardened(flags_module.PLAINTEXT_TEACH):
            return redirect(request.url.replace("http://", "https://", 1).replace(":5001", ":5000"), code=308)
        if request.path == "/api/telemetry" and hardening.is_hardened(flags_module.PLAINTEXT_EXERCISE):
            return redirect(request.url.replace("http://", "https://", 1).replace(":5001", ":5000"), code=308)
        return None

    @app.route("/favicon.ico")
    def favicon():
        # Browsers request this exact path automatically on first load,
        # independent of any <link rel="icon"> tag and regardless of which
        # page (portal or /mail) they landed on first -- without a route
        # here that request 404s and some browsers never pick up the SVG
        # declared in <head> as a result. Explicit mimetype rather than
        # relying on auto-detection, which depends on the container's own
        # mimetypes database and isn't guaranteed to match dev environments.
        return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")

    @app.route("/robots.txt")
    def robots_txt():
        # /admin/diagnostics and /tools/meter-lookup are real; /backup/ and
        # /old/ are decoys that don't resolve to anything -- normal
        # robots.txt noise, and it keeps the real hints from being the
        # only lines here. /ops/ is deliberately NOT hinted at -- that one
        # stays found by accident or not at all.
        body = "User-agent: *\nDisallow: /admin/diagnostics\nDisallow: /tools/meter-lookup\nDisallow: /backup/\nDisallow: /old/\n"
        return Response(body, mimetype="text/plain")

    return app
