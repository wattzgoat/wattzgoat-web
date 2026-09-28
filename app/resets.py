"""Shared reset helpers -- deliberately dependency-free (stdlib only) so both
the participant process and the separate instructor process can import them
without dragging in each other's blueprints.

Two things live here:

- firmware_dir(): where the insecure-file-upload exercises write. It sits
  next to the database (DB_PATH's directory) rather than inside the app
  package, so that in a paired deployment it lives on the SAME shared volume
  both containers already mount at /app/data -- which is the only reason the
  instructor process can clear uploads that were written by the participant
  process at all (two containers don't otherwise share a filesystem).
- reset_app_state(): restore the app's own data to its seeded state while
  keeping the participant-tracking tables exactly as they are.
"""
import os
import shutil
import sqlite3


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
