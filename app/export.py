"""CSV export of participant progress, for the instructor dashboard and the
standalone /participants console. Two files:

- summary: one row per participant (rank, nickname, flags found, first and
  last activity), in leaderboard order.
- detail: one row per redeemed flag (who, which flag, when, which account).

Only redemption status and timestamps are exported, never a flag's actual
value. Times are UTC, as stored.

Spreadsheet formula injection: nicknames are typed by participants, so a
cell that starts with = + - @ (or a tab or carriage return) could be run as
a formula when the file is opened in Excel or Sheets. Any such text cell gets
a leading apostrophe, which spreadsheets show as plain text.
"""
import csv
import io
from datetime import datetime, timezone

from flask import Response

from .db import get_db
from .flags import CATALOG

_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")
_CATALOG = {key: (category, name) for key, category, name in CATALOG}


def safe_cell(value):
    """A value ready to write to CSV: numbers pass through, None becomes an
    empty cell, and text that could be read as a formula is neutralized."""
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    if text.startswith(_FORMULA_STARTS):
        return "'" + text
    return text


def _standings():
    return get_db().execute(
        "SELECT r.participant_id AS participant_id, n.nickname AS nickname, "
        "COUNT(*) AS flags_found, MIN(r.redeemed_at) AS first_activity, MAX(r.redeemed_at) AS last_activity "
        "FROM flag_redemptions r LEFT JOIN participant_nicknames n ON n.participant_id = r.participant_id "
        "GROUP BY r.participant_id ORDER BY flags_found DESC, last_activity ASC"
    ).fetchall()


def _csv_response(prefix, header, rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(cell) for cell in row])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    # The leading BOM makes Excel read the file as UTF-8, so non-English
    # nicknames display correctly.
    resp = Response("\ufeff" + buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{prefix}-{stamp}.csv"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


def summary_response():
    total = len(CATALOG)
    rows = [
        (rank, s["participant_id"], s["nickname"], s["flags_found"], total, s["first_activity"], s["last_activity"])
        for rank, s in enumerate(_standings(), start=1)
    ]
    header = ["Rank", "Participant ID", "Nickname", "Flags found", "Total flags", "First activity (UTC)", "Last activity (UTC)"]
    return _csv_response("wattzgoat-leaderboard-summary", header, rows)


def detail_response():
    standings = _standings()
    rank = {s["participant_id"]: i for i, s in enumerate(standings, start=1)}
    nick = {s["participant_id"]: s["nickname"] for s in standings}
    redemptions = get_db().execute(
        "SELECT id, participant_id, flag_key, redeemed_by, redeemed_at FROM flag_redemptions"
    ).fetchall()
    redemptions = sorted(redemptions, key=lambda r: (rank[r["participant_id"]], r["redeemed_at"], r["id"]))
    rows = []
    for r in redemptions:
        category, name = _CATALOG.get(r["flag_key"], ("", ""))
        rows.append((
            r["participant_id"], nick.get(r["participant_id"]), r["flag_key"], category, name,
            r["redeemed_at"], r["redeemed_by"],
        ))
    header = ["Participant ID", "Nickname", "Flag key", "Category", "Flag name", "Redeemed at (UTC)", "Redeemed by (account)"]
    return _csv_response("wattzgoat-flag-detail", header, rows)
