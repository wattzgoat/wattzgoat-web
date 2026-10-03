import os
from datetime import datetime, timezone

from flask import Flask, Response, g, redirect, request, send_from_directory, url_for

from . import db as db_module
from . import flags as flags_module
from . import guided, hardening


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "/app/data/app.db")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "wattzgoat-training-lab")

    db_module.init_app(app)

    app.config["TRAINER_MODE"] = _truthy_env("TRAINER_DASHBOARD")
    if app.config["TRAINER_MODE"]:
        app.config["TRAINER_DB_PATH"] = os.environ.get("TRAINER_DB_PATH", "/app/trainer_data/trainer.db")
        app.config["PARTICIPANT_BASE_URL"] = os.environ.get("PARTICIPANT_BASE_URL", "")

        from . import trainer_auth
        from .trainer import bp as trainer_bp
        app.teardown_appcontext(trainer_auth.close_trainer_db)
        app.register_blueprint(trainer_bp)

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

    app.jinja_env.globals["participant_display"] = current_participant_display
    app.jinja_env.globals["guided_state"] = guided.state
    app.jinja_env.globals["guided_panel"] = guided.panel
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
            # Guided mode is offered on a standalone instance only when GUIDED_MODE=true.
            app.config["GUIDED_MODE"] = _truthy_env("GUIDED_MODE")
            app.register_blueprint(standalone_bp)
            app.logger.warning("STANDALONE=true -- hidden /participants console is ENABLED on this instance.")

    @app.route("/")
    def index():
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["role"] == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("customer.dashboard"))

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
        return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")

    @app.route("/robots.txt")
    def robots_txt():
        body = "User-agent: *\nDisallow: /admin/diagnostics\nDisallow: /tools/meter-lookup\nDisallow: /backup/\nDisallow: /old/\n"
        return Response(body, mimetype="text/plain")

    return app
