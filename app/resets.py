"""Shared reset helpers, used by the separate instructor process
(app/trainer.py), the standalone /participants console (app/standalone.py)
and the participant-side /ops/__reset_lab__. Only stdlib at import time --
the one personalize import is deferred into reset_lab_state() -- so this
module never drags a role's blueprints into another role's process.

What lives here:

- firmware_dir(): where the insecure-file-upload exercises write. It sits
  next to the database (DB_PATH's directory) rather than inside the app
  package, so that in a paired deployment it lives on the SAME shared volume
  both containers already mount at /app/data -- which is the only reason the
  instructor process can clear uploads that were written by the participant
  process at all (two containers don't otherwise share a filesystem).
- reset_lab_state(): the full wipe (seed.db file-swap, new flag secret,
  uploaded files removed).
- reset_app_state(): restore the app's own data to its seeded state while
  keeping the participant-tracking tables exactly as they are.
- NOTICES / notice_from_args(): the fixed vocabulary of toast messages the
  redirect-after-reset flow shows.
"""
import glob
import os
import shutil
import sqlite3
import tempfile

from .guidance import GUIDED_META_KEY


def firmware_dir() -> str:
    explicit = os.environ.get("FIRMWARE_DIR")
    if explicit:
        return explicit
    db_path = os.environ.get("DB_PATH", "/app/data/app.db")
    return os.path.join(os.path.dirname(db_path) or ".", "firmware")


def clear_firmware_files(directory: str | None = None) -> int:
    """Remove everything under the firmware directory (uploads and the
    canary file). Returns how many files were removed; a missing directory
    is not an error -- nothing has been uploaded yet."""
    directory = directory or firmware_dir()
    if not os.path.isdir(directory):
        return 0
    removed = sum(len(files) for _, _, files in os.walk(directory))
    shutil.rmtree(directory)
    return removed


# Tables restored from seed.db by reset_app_state(). Everything else in the
# database (flag_redemptions, participant_nicknames, lab_meta) is left alone.
#
# - sessions: restored too, which leaves only the fixture row planted for the
#   predictable-session-ID exercise -- i.e. every live login expires.
# - hardening_state: restored too, i.e. every toggle returns to vulnerable.
APP_TABLES = (
    "users", "sessions", "emails", "meters", "readings", "bills",
    "recharges", "solar_exports", "tickets", "alarms", "hardening_state",
)


def reset_app_state(db_path: str, seed_path: str) -> None:
    """Restore APP_TABLES from seed.db inside one transaction, so a failure
    leaves the live database untouched. Does not touch flag_redemptions,
    participant_nicknames or lab_meta (so redemptions, participant IDs,
    nicknames and the flag secret all survive)."""
    if not os.path.isfile(seed_path):
        raise FileNotFoundError(f"no seed.db to reset from at {seed_path}")

    conn = sqlite3.connect(db_path, timeout=15, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("ATTACH DATABASE ? AS seed", (seed_path,))
        conn.execute("BEGIN IMMEDIATE")
        try:
            for table in APP_TABLES:
                live_cols = [r[1] for r in conn.execute(f"PRAGMA main.table_info({table})")]
                seed_cols = {r[1] for r in conn.execute(f"PRAGMA seed.table_info({table})")}
                cols = [c for c in live_cols if c in seed_cols]
                if not cols:
                    raise RuntimeError(f"table {table!r} missing from live or seed database")
                col_list = ", ".join(cols)
                conn.execute(f"DELETE FROM main.{table}")
                conn.execute(f"INSERT INTO main.{table} ({col_list}) SELECT {col_list} FROM seed.{table}")

            # AUTOINCREMENT high-water marks follow the restored rows.
            names = ",".join("?" for _ in APP_TABLES)
            conn.execute(f"DELETE FROM main.sqlite_sequence WHERE name IN ({names})", APP_TABLES)
            conn.execute(
                f"INSERT INTO main.sqlite_sequence (name, seq) "
                f"SELECT name, seq FROM seed.sqlite_sequence WHERE name IN ({names})",
                APP_TABLES,
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def reset_lab_state(db_path: str, seed_path: str) -> None:
    """Full wipe: swap seed.db over the live database, rotate the flag
    secret, and remove uploaded files. The swap is a write-to-temp-file +
    os.replace() -- a single atomic rename -- rather than an in-place copy,
    because the app is never truly idle (the meter simulators hit the DB on
    their own every 20-40s) and a concurrent connection must only ever see
    the complete old file or the complete new one. The temp file lives next
    to db_path because os.replace() is only atomic within one filesystem."""
    from .personalize import regenerate_lab_secret

    if not os.path.isfile(seed_path):
        raise FileNotFoundError(f"no seed.db to reset from at {seed_path}")

    # The instructor's guided-mode switch is a setting for how the session is
    # being run, not lab state, so it is read before the swap and put back after.
    guided_value = None
    try:
        probe = sqlite3.connect(db_path)
        try:
            row = probe.execute("SELECT value FROM lab_meta WHERE key = ?", (GUIDED_META_KEY,)).fetchone()
            guided_value = row[0] if row else None
        finally:
            probe.close()
    except sqlite3.Error:
        guided_value = None

    db_dir = os.path.dirname(db_path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".app_db_reset_", dir=db_dir)
    try:
        os.close(fd)
        shutil.copyfile(seed_path, tmp_path)
        os.replace(tmp_path, db_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    # WAL/SHM sidecars are cleaned up AFTER the swap, not before.
    for aux in glob.glob(db_path + "-*"):
        os.remove(aux)

    # New secret on the now-live DB: flag VALUES change on every reset.
    fresh_conn = sqlite3.connect(db_path)
    try:
        regenerate_lab_secret(fresh_conn)
        if guided_value is not None:
            fresh_conn.execute(
                "INSERT INTO lab_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (GUIDED_META_KEY, guided_value),
            )
            fresh_conn.commit()
    finally:
        fresh_conn.close()

    clear_firmware_files()


# Reset actions redirect back to a page with a short, fixed-vocabulary notice
# code in the query string, rendered as a toast. Only codes in this table are
# ever shown; the only dynamic values are a clamped integer and a short,
# Jinja-escaped participant ID prefix -- nothing from the query string is
# rendered as free text.
NOTICES = {
    "lab_reset": ("success", "Lab reset to its seeded state"),
    "lab_reset_failed": ("error", "Lab reset failed -- see the container logs"),
    "app_reset": ("success", "App reset to its seeded state"),
    "app_reset_failed": ("error", "App reset failed -- nothing was changed; see the container logs"),
    "app_reset_files_failed": (
        "error",
        "App data was reset, but uploaded firmware files could not be removed -- see the container logs",
    ),
    "redemptions_reset_all": ("success", "All redemptions cleared"),
    "redemptions_reset_all_failed": ("error", "Reset all redemptions failed -- see the container logs"),
    "redemptions_reset": ("success", "Redemptions cleared for participant"),
    "redemptions_reset_failed": ("error", "Reset redemption failed -- see the container logs"),
    "redemptions_reset_no_id": ("error", "Reset redemption failed -- no participant ID given"),
}


def notice_from_args(args):
    """{'kind', 'text'} for the request's ?notice= code, or None."""
    code = args.get("notice")
    if code not in NOTICES:
        return None
    kind, text = NOTICES[code]
    if code == "redemptions_reset":
        pid = (args.get("pid") or "")[:8]
        if pid:
            text += f" {pid}"
    count = args.get("n", type=int)
    if count is not None and kind == "success" and code != "lab_reset":
        text += f" ({max(count, 0)} removed)"
    return {"kind": kind, "text": text + "."}
