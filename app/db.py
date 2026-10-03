import re
import sqlite3

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(e=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)


_NEAR_FRAGMENT = re.compile(r'near "(.+?)"|unrecognized token: "(.+?)"')


def mysql_style_error(sqlite_error: Exception) -> str:
    message = str(sqlite_error)
    m = _NEAR_FRAGMENT.search(message)
    fragment = next((g for g in (m.groups() if m else ()) if g is not None), message)
    return (
        "You have an error in your SQL syntax; check the manual that corresponds "
        "to your MySQL server version for the right syntax to use near "
        f"'{fragment}' at line 1"
    )
