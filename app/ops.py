import glob
import os
import shutil

from flask import Blueprint, abort, current_app, jsonify, redirect, request, url_for

from . import assistant, auth

bp = Blueprint("ops", __name__, url_prefix="/ops")

# Deliberately NOT wired into any nav, and deliberately not gated behind a
# token -- this route only affects the single isolated instance it's
# running in, so there's no real security boundary to protect. What
# matters is that it works without a container restart: copy the pristine
# seed.db back over the live app.db, and drop any WAL/SHM files so a
# connection doesn't read stale journal data against the freshly-copied
# file. The session-token counter is intentionally left alone (it just
# resumes where it was); the rate-limit counters are cleared below.
@bp.route("/__reset_lab__", methods=["POST"])
def reset_lab():
    db_path = current_app.config["DB_PATH"]
    seed_path = os.environ.get("SEED_DB_PATH", "/app/data/seed.db")

    if not os.path.isfile(seed_path):
        abort(500, "no seed.db to reset from")

    for aux in glob.glob(db_path + "-*"):
        os.remove(aux)
    shutil.copyfile(seed_path, db_path)

    # The attempt counters behind the rate-limiting flags live in memory, so
    # they have to be cleared by hand -- otherwise the very next failed
    # login after a reset would already count as attempt #6.
    auth._login_attempts.clear()
    auth._reset_attempts.clear()
    assistant._pending_admin_actions.clear()

    # Browsers (the admin nav button) land back on the login page, since the
    # reset also wipes every session; curl/scripts still get JSON.
    if request.accept_mimetypes.best_match(["application/json", "text/html"]) == "text/html":
        resp = redirect(url_for("auth.login", reset=1))
        resp.delete_cookie("wgs_session")
        return resp
    return jsonify({"status": "reset"})
