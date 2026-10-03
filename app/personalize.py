"""Participant identity and per-participant flag values."""
import hashlib
import hmac
import re
import secrets

from flask import Blueprint, g, jsonify, request

from .db import get_db

bp = Blueprint("personalize", __name__)

PARTICIPANT_COOKIE = "wg_pid"
LAB_SECRET_KEY = "flag_secret"

NICKNAME_MAX_LEN = 24
_NICKNAME_RE = re.compile(r"^[\w \-'.]{1,%d}$" % NICKNAME_MAX_LEN, re.UNICODE)

_ADJECTIVES = [
    "SILENT", "IRON", "CRIMSON", "OBSIDIAN", "QUIET", "VELVET", "HUSHED", "AMBER",
    "HOLLOW", "SEVERED", "NIGHT", "PALE", "RUSTY", "OPEN", "SHADOW", "COPPER",
    "BORROWED", "BLACKOUT", "STALE", "BACKDOOR", "WRONG", "FRACTURED", "COUNTING",
    "FORGED", "LOUD", "HIDDEN", "SUNBURST", "CRACKED", "TWO_FACED", "LOOSE",
    "ROGUE", "PILLOW", "TROJAN", "ECHO", "COLD", "GILDED", "FROZEN", "BROKEN",
    "SUNKEN", "RUSTED", "MASKED", "VEILED", "DRIFTING", "SCATTERED", "TANGLED",
    "WEATHERED", "FADED", "JAGGED", "MUTED", "GHOSTLY", "SPARE", "BLUNT", "STEADY",
    "BRITTLE", "DORMANT", "RESTLESS", "SUNLIT", "MOONLESS", "WINDING", "NARROW",
    "DISTANT", "FLICKERING", "CROOKED", "LINGERING", "UNSEEN", "IDLE", "STIFF",
    "WEARY", "CRUMBLING", "SPRAWLING", "SUDDEN", "STARK", "GRIM", "WORN",
]
_NOUNS = [
    "FALCON", "SENTINEL", "WIRE", "RAVEN", "CIRCUIT", "HAMMER", "STORM", "VIPER",
    "POINT", "LINE", "COURIER", "HORSE", "KEYCARD", "MANIFEST", "LEDGER", "KEY",
    "BADGE", "ECHO", "SIGNAL", "TICKET", "DOOR", "GLASS", "SHEEP", "PAPERS",
    "WHISPER", "WALLET", "TALLY", "MASK", "CANNON", "LIPS", "AGENT", "TALK",
    "MEMO", "CHAMBER", "TRAIL", "LANTERN", "HARBOR", "BEACON", "ANCHOR", "SPIRE",
    "HOLLOW", "RELAY", "SOCKET", "VALVE", "GAUGE", "CONDUIT", "GRID", "FUSE",
    "CIRCUIT_BOARD", "TOWER", "VAULT", "LATCH", "HINGE", "SHUTTER", "FRAME",
    "LEDGE", "CORRIDOR", "STAIRWELL", "HATCH", "PANEL", "BREAKER", "TERMINAL",
    "JUNCTION", "OUTLET", "CABLE", "MANIFOLD", "TURBINE", "RESERVOIR", "SLUICE",
    "CISTERN", "FLARE", "EMBER", "CINDER", "DRIFT", "CURRENT",
]


def _generate_participant_id() -> str:
    return secrets.token_hex(8)


@bp.before_app_request
def load_participant():
    token = request.cookies.get(PARTICIPANT_COOKIE)
    if token:
        g.participant_id = token
        g.new_participant = False
    else:
        g.participant_id = _generate_participant_id()
        g.new_participant = True


@bp.after_app_request
def set_participant_cookie(resp):
    if g.get("new_participant"):
        if request.is_secure:
            resp.set_cookie(
                PARTICIPANT_COOKIE, g.participant_id, max_age=60 * 60 * 24 * 365,
                samesite="None", secure=True,
            )
        else:
            resp.set_cookie(PARTICIPANT_COOKIE, g.participant_id, max_age=60 * 60 * 24 * 365)
    return resp


def current_participant_display() -> str | None:
    """The participant's name as shown in the page header."""
    participant_id = g.get("participant_id")
    return display_identity(participant_id) if participant_id else None


def current_participant_has_nickname() -> bool:
    participant_id = g.get("participant_id")
    return bool(participant_id and get_nickname(participant_id))


def get_lab_secret() -> str:
    db = get_db()
    row = db.execute("SELECT value FROM lab_meta WHERE key = ?", (LAB_SECRET_KEY,)).fetchone()
    if row is None:
        return secrets.token_hex(32)
    return row["value"]


def regenerate_lab_secret(conn) -> None:
    """Called by ops.reset_lab() on the freshly-swapped-in DB connection,
    after the atomic file swap -- rotates the secret so flag values
    change on every reset, not just at first boot."""
    conn.execute(
        "INSERT INTO lab_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (LAB_SECRET_KEY, secrets.token_hex(32)),
    )
    conn.commit()


def short_participant_id(participant_id: str) -> str:
    """The first 8 characters of a participant ID."""
    return participant_id[:8]


def get_nickname(participant_id: str) -> str | None:
    db = get_db()
    row = db.execute(
        "SELECT nickname FROM participant_nicknames WHERE participant_id = ?", (participant_id,)
    ).fetchone()
    return row["nickname"] if row else None


def display_identity(participant_id: str) -> str:
    """The nickname if there is one, with the short participant ID in brackets."""
    nickname = get_nickname(participant_id)
    short_id = short_participant_id(participant_id)
    return f"{nickname} ({short_id})" if nickname else short_id


def set_nickname(participant_id: str, requested: str) -> str:
    """Set a participant's nickname, adding a number if another participant already has it."""
    db = get_db()
    candidate = requested
    suffix = 1
    while True:
        collision = db.execute(
            "SELECT 1 FROM participant_nicknames WHERE nickname = ? AND participant_id != ?",
            (candidate, participant_id),
        ).fetchone()
        if collision is None:
            break
        suffix += 1
        candidate = f"{requested}-{suffix}"

    db.execute(
        "INSERT INTO participant_nicknames (participant_id, nickname) VALUES (?, ?) "
        "ON CONFLICT(participant_id) DO UPDATE SET nickname = excluded.nickname",
        (participant_id, candidate),
    )
    db.commit()
    return candidate


@bp.route("/participant/nickname", methods=["POST"])
def submit_nickname():
    """Save the nickname a participant chose."""
    raw = (request.form.get("nickname") or "").strip()
    if not raw or not _NICKNAME_RE.match(raw):
        return jsonify({
            "error": f"Nickname must be 1-{NICKNAME_MAX_LEN} characters "
                     "(letters, numbers, spaces, - ' . only).",
        }), 400

    stored = set_nickname(g.participant_id, raw)
    return jsonify({"nickname": stored, "display": display_identity(g.participant_id)})


def get_flag(flag_key: str, participant_id: str) -> str:
    secret = get_lab_secret()
    digest = hmac.new(secret.encode(), f"{flag_key}:{participant_id}".encode(), hashlib.sha256).digest()
    adjective = _ADJECTIVES[digest[0] % len(_ADJECTIVES)]
    noun = _NOUNS[digest[1] % len(_NOUNS)]
    suffix = digest[2:6].hex().upper()
    return f"FLAG{{{adjective}_{noun}_{suffix}}}"


def participant_standings():
    """Participants ranked by flags found; ties go to whoever got there first."""
    rows = get_db().execute(
        "SELECT participant_id, COUNT(*) AS flags_redeemed, MAX(redeemed_at) AS last_activity "
        "FROM flag_redemptions GROUP BY participant_id ORDER BY flags_redeemed DESC, last_activity ASC"
    ).fetchall()
    return [
        {
            "participant_id": row["participant_id"],
            "display": display_identity(row["participant_id"]),
            "flags_redeemed": row["flags_redeemed"],
            "last_activity": row["last_activity"],
        }
        for row in rows
    ]
