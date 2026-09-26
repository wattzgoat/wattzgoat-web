"""
Participant identity and personalized flag derivation.

Why identity is tracked separately from login: several categories are
built around participants sharing the SAME login (the two ops admin
accounts, most obviously), so "which account is logged in" can't be used
to tell participants apart. Instead, every visitor gets an opaque
participant_id the first time they hit the app at all -- before any
login -- via a long-lived cookie, completely independent of session/auth
state. This runs on every request, authenticated or not, since a few
flags (rate limiting, the plaintext header) are reachable pre-login.

Flag values are derived, not stored: HMAC(secret, f"{flag_key}:
{participant_id}") mapped onto a two-word codename bank, so the result
still looks like the existing FLAG{ADJECTIVE_NOUN} style. The secret
lives in the DB (lab_meta table) and is regenerated at seed time and
again on every /ops/__reset_lab__ run (see app/ops.py), so flag values
also rotate on a lab reset rather than staying fixed forever -- which
incidentally also means a leaked walkthrough from one class doesn't hand
future participants a working answer key.
"""
import hashlib
import hmac
import secrets

from flask import Blueprint, g, request

from .db import get_db

bp = Blueprint("personalize", __name__)

PARTICIPANT_COOKIE = "wg_pid"
LAB_SECRET_KEY = "flag_secret"

# Two independent word banks -- picked by different bytes of the HMAC
# digest, so the result reads as an ADJECTIVE_NOUN codename in the same
# style as the original static catalog (FLAG{IRON_SENTINEL}, etc.).
# Sized to keep collisions low at realistic class sizes without needing
# to be cryptographically rigorous -- this personalizes flags to deter
# casually handing someone else the answer string, it isn't a security
# boundary in its own right.
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
        # ~1 year, plain (not HttpOnly) -- this is an identifier, not a
        # secret, and nothing sensitive depends on JS being unable to
        # read it.
        resp.set_cookie(PARTICIPANT_COOKIE, g.participant_id, max_age=60 * 60 * 24 * 365)
    return resp


def get_lab_secret() -> str:
    db = get_db()
    row = db.execute("SELECT value FROM lab_meta WHERE key = ?", (LAB_SECRET_KEY,)).fetchone()
    if row is None:
        # Shouldn't happen against a properly seeded DB, but fail
        # gracefully (a fresh random secret this request only) rather
        # than 500 the whole app if it does.
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


def get_flag(flag_key: str, participant_id: str) -> str:
    secret = get_lab_secret()
    digest = hmac.new(secret.encode(), f"{flag_key}:{participant_id}".encode(), hashlib.sha256).digest()
    adjective = _ADJECTIVES[digest[0] % len(_ADJECTIVES)]
    noun = _NOUNS[digest[1] % len(_NOUNS)]
    # The word pair alone is only ~5,500 possible combinations -- far too
    # small a space once you multiply 37 keys by any realistic number of
    # participants (the birthday paradox makes an accidental collision
    # between two unrelated (key, participant) pairs a real, observed
    # event, not a theoretical edge case). The word pair stays for
    # readability/flavor; this 4-byte hex suffix (32 bits, ~4.3 billion
    # values) is what actually keeps every (key, participant) pair
    # distinct at any real class size.
    suffix = digest[2:6].hex().upper()
    return f"FLAG{{{adjective}_{noun}_{suffix}}}"
