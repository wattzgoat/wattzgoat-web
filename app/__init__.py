import os
from datetime import datetime, timezone

from flask import Flask, Response, g, redirect, request, send_from_directory, url_for

from . import db as db_module
from . import flags as flags_module
from . import hardening


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "/app/data/app.db")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "wattzgoat-training-lab")

    db_module.init_app(app)

    # Next-phase item 1: TRAINER_DASHBOARD=true switches this container
    # to run as a dedicated trainer-dashboard role INSTEAD OF the
    # participant-facing app -- same image, same INSTANCE_HOST-style
    # boot-time role selection entrypoint.sh/run.py already use for
    # HARDENING_MODE=all (see app/hardening.py), extended to a third
    # role. The trainer role registers only app/trainer.py's blueprint
    # (own login, own DB, own everything -- see that module's docstring)
    # and returns early: no auth/customer/admin/participant surface at
    # all on this process, on purpose -- there is nothing here for a
    # participant to ever reach.
    app.config["TRAINER_MODE"] = _truthy_env("TRAINER_DASHBOARD")
    if app.config["TRAINER_MODE"]:
        app.config["TRAINER_DB_PATH"] = os.environ.get("TRAINER_DB_PATH", "/app/trainer_data/trainer.db")
        # Pure UI convenience -- the "WattzGOAT Portal" nav link's target.
        # No API calls ever go out over this; the participant app's own
        # index() route (below) already does the context-aware
        # dashboard/admin-dashboard/login redirect on ITS OWN session
        # state once the browser follows the link there, so the trainer
        # process itself doesn't need to know or care which one applies.
        app.config["PARTICIPANT_BASE_URL"] = os.environ.get("PARTICIPANT_BASE_URL", "")

        from . import trainer_auth
        from .trainer import bp as trainer_bp
        app.teardown_appcontext(trainer_auth.close_trainer_db)
        app.register_blueprint(trainer_bp)

        # Bare "/" and the pre-rename "/trainer/..." path (this
        # blueprint's URL prefix used to be /trainer before it became
        # /instructor) both 404 with nothing else registered on this
        # process -- redirect both to the equivalent /instructor/... path
        # instead of leaving an old bookmark or a bare port dead-end.
        @app.route("/")
        def _root_redirect():
            from flask import redirect, url_for
            return redirect(url_for("trainer.dashboard"))

        @app.route("/trainer/", defaults={"subpath": ""})
        @app.route("/trainer/<path:subpath>")
        def _old_trainer_redirect(subpath):
            from flask import redirect
            return redirect(f"/instructor/{subpath}")

        return app

    # Phase 6: exposed so templates can branch on hardening state and
    # embed a real anti-CSRF token directly (see CSRF_TEACH/CSRF_EXERCISE
    # in customer.py + account.html/dashboard.html, SXSS_TEACH/
    # SXSS_EXERCISE in dashboard.html/admin_tickets.html, DEVADMIN_LEAK in
    # login.html, ASSISTANT_OUTPUT_XSS in _assistant_widget.html) without
    # every view function having to thread an extra flag through its own
    # render_template() call.
    app.jinja_env.globals["is_hardened"] = hardening.is_hardened
    app.jinja_env.globals["csrf_token"] = hardening.csrf_token
    # Header date (base.html) -- server-rendered, UTC, date only.
    app.jinja_env.globals["current_year"] = lambda: datetime.now(timezone.utc).year
    app.jinja_env.globals["today_utc"] = lambda: datetime.now(timezone.utc).strftime("%a %d %b %Y")

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
    from .personalize import current_participant_display, current_participant_has_nickname

    # Next-phase item 6: participant nickname display, read by
    # base.html's identity chip and nickname-prompt trigger.
    app.jinja_env.globals["participant_display"] = current_participant_display
    app.jinja_env.globals["participant_has_nickname"] = current_participant_has_nickname

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

    # Hidden /participants console (leaderboard + the three resets) for
    # instances WITHOUT a paired instructor container. Off unless
    # STANDALONE=true, and it also needs STANDALONE_PASSWORD -- see
    # app/standalone.py. A HARDENING_MODE=all reference instance never gets
    # it (hardening toggles and redemptions don't apply there).
    if _truthy_env("STANDALONE"):
        password = os.environ.get("STANDALONE_PASSWORD", "")
        if hardening.FORCE_ALL:
            app.logger.warning("STANDALONE=true ignored: HARDENING_MODE=all instances have no /participants console.")
        elif not password:
            app.logger.warning(
                "STANDALONE=true but STANDALONE_PASSWORD is not set -- the /participants console stays DISABLED."
            )
        else:
            from .standalone import bp as standalone_bp
            app.config["STANDALONE_PASSWORD"] = password
            app.register_blueprint(standalone_bp)
            app.logger.warning("STANDALONE=true -- hidden /participants console is ENABLED on this instance.")

    # Next-phase item 1: app/trainer.py's blueprint is registered ONLY
    # under TRAINER_DASHBOARD=true (see above) -- no longer part of the
    # participant-facing app at all. base.html's admin nav no longer
    # links to it either (see base.html).

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
