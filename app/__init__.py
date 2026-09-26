import os

from flask import Flask, Response, g, redirect, send_from_directory, url_for

from . import db as db_module


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "/app/data/app.db")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "wattzgoat-training-lab")

    db_module.init_app(app)

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

    @app.route("/")
    def index():
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["role"] == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("customer.dashboard"))

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
