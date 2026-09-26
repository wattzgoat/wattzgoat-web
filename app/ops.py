import glob
import os
import shutil
import sqlite3
import tempfile

from flask import Blueprint, abort, current_app, jsonify, redirect, request, url_for

from . import assistant, auth
from .personalize import regenerate_lab_secret

bp = Blueprint("ops", __name__, url_prefix="/ops")

# Wired into the admin nav ("Reset Lab" button in base.html) and
# deliberately not gated behind a token beyond ordinary admin login --
# this route only affects the single isolated instance it's running in,
# so there's no additional security boundary to protect beyond that.
#
# What matters is that it works without a container restart: copy the
# pristine seed.db back over the live app.db, and drop any WAL/SHM files
# so a connection doesn't read stale journal data against the
# freshly-copied file. The session-token counter is intentionally left
# alone (it just resumes where it was); the rate-limit counters are
# cleared below.
#
# The copy itself is done via write-to-temp-then-os.replace() rather than
# copying directly over db_path in place. shutil.copyfile() onto a live
# path truncates and streams into the destination file over time, which
# leaves a real window where a concurrent connection (this app is never
# fully idle -- the meter simulator threads hit the DB on their own every
# 20-40s regardless of what else is happening) can open a half-written or
# momentarily empty file and see a schema-less database ("no such table:
# meters"). os.replace() is a single filesystem-level rename, not a
# content copy, so there's no intermediate state for a concurrent
# connection to ever observe -- it's always either the complete old file
# or the complete new one.
@bp.route("/__reset_lab__", methods=["POST"])
def reset_lab():
    db_path = current_app.config["DB_PATH"]
    seed_path = os.environ.get("SEED_DB_PATH", "/app/data/seed.db")

    if not os.path.isfile(seed_path):
        abort(500, "no seed.db to reset from")

    # Temp file lives in the same directory as db_path on purpose --
    # os.replace() is only guaranteed atomic within a single filesystem,
    # so a temp dir on a different mount (e.g. /tmp) would silently
    # degrade this back into a non-atomic cross-filesystem copy.
    db_dir = os.path.dirname(db_path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".app_db_reset_", dir=db_dir)
    try:
        os.close(fd)
        shutil.copyfile(seed_path, tmp_path)
        os.replace(tmp_path, db_path)
    except Exception:
        # Don't leave a half-written temp file lying around if the copy
        # itself fails partway through.
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    # WAL/SHM cleanup happens *after* the swap, not before -- doing it
    # first (as the old version did) briefly left the pre-reset database
    # without its journal sidecar files while the copy was still in
    # flight, which was its own smaller version of the same problem.
    for aux in glob.glob(db_path + "-*"):
        os.remove(aux)

    # Rotate the personalization secret on the now-live DB -- this is
    # what makes flag VALUES change on every reset, not just at first
    # boot (the file swap above alone would restore the same secret that
    # was baked into seed.db at the original seeding pass). A short-lived
    # connection of its own, not g.db, since this runs outside normal
    # request-scoped DB access.
    fresh_conn = sqlite3.connect(db_path)
    try:
        regenerate_lab_secret(fresh_conn)
    finally:
        fresh_conn.close()

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
