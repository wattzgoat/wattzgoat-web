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
import re
import secrets

from flask import Blueprint, g, jsonify, request

from .db import get_db

bp = Blueprint("personalize", __name__)

PARTICIPANT_COOKIE = "wg_pid"
LAB_SECRET_KEY = "flag_secret"

# Next-phase: participant nickname prompt. Plain display text, not an
# identity/auth mechanism -- kept short and printable-only so it's safe
# to render directly (still HTML-escaped by Jinja's autoescaping like
# everything else, this isn't a trust boundary, just a sanity limit on
# what's worth accepting as a "name").
NICKNAME_MAX_LEN = 24
_NICKNAME_RE = re.compile(r"^[\w \-'.]{1,%d}$" % NICKNAME_MAX_LEN, re.UNICODE)

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
    # Phase 8 (revised): only issue wg_pid on genuine first contact
    # (g.new_participant, same condition as before this project's CSRF
    # fix) -- NOT on every login, even an HTTPS one. An earlier version
    # of this also re-issued it at login whenever the login was HTTPS,
    # to cover a visitor whose first-ever contact happened to be the
    # plaintext mirror. That traded a narrow edge case for a worse
    # problem: a server has no way to know from a request alone whether
    # the client's existing wg_pid already carries the upgraded
    # Secure/SameSite=None attributes, so re-issuing it identically on
    # every login is a no-op for a real browser but NOT for a client
    # that manages its cookie jar by domain -- re-setting the same name
    # with a concrete request domain, when the client had it stored
    # under an unspecified/different domain (e.g. a test harness doing
    # session.cookies.set("wg_pid", ...) with no domain given), produces
    # a SECOND, distinct cookie entry rather than replacing the first.
    # Any later read of that cookie by name alone then fails outright
    # (requests' CookieConflictError is exactly this). This is exactly
    # what broke tests/hardening/test_toggle_17_assistant.py in CI.
    #
    # The dominant real case -- a participant whose first-ever contact
    # is the normal HTTPS landing page -- is still fully covered by
    # g.new_participant alone, since this branch already picks Secure/
    # SameSite=None for an HTTPS first contact. Only the narrower
    # plaintext-mirror-first case goes back to carrying an ordinary
    # same-site wg_pid if that same visitor later logs in over HTTPS
    # and tests CSRF_TEACH/CSRF_EXERCISE -- accepted as a known gap
    # rather than reintroducing a cookie-identity bug for every client.
    #
    # Secure/SameSite=None only on an HTTPS request -- same pairing rule
    # and same plaintext-mirror reasoning as wgs_session in auth.py: a
    # Secure cookie set over plaintext would never be sent back on the
    # next plaintext request at all.
    if g.get("new_participant"):
        # ~1 year, plain (not HttpOnly) -- this is an identifier, not a
        # secret, and nothing sensitive depends on JS being unable to
        # read it.
        if request.is_secure:
            resp.set_cookie(
                PARTICIPANT_COOKIE, g.participant_id, max_age=60 * 60 * 24 * 365,
                samesite="None", secure=True,
            )
        else:
            resp.set_cookie(PARTICIPANT_COOKIE, g.participant_id, max_age=60 * 60 * 24 * 365)
    return resp


def current_participant_display() -> str | None:
    """Jinja global (see app/__init__.py) -- base.html's identity chip
    and nickname-prompt trigger both read this rather than querying the
    DB directly from the template. None only if participant identity
    somehow isn't loaded at all (shouldn't happen on any real request --
    load_participant() runs before every one), which templates treat the
    same as "no nickname yet"."""
    participant_id = g.get("participant_id")
    return display_identity(participant_id) if participant_id else None


def current_participant_has_nickname() -> bool:
    participant_id = g.get("participant_id")
    return bool(participant_id and get_nickname(participant_id))


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


def short_participant_id(participant_id: str) -> str:
    """The small parenthetical form -- first 8 hex chars of the full
    16-char participant_id token, enough to disambiguate at realistic
    class sizes without printing the full token everywhere it's shown
    alongside a nickname."""
    return participant_id[:8]


def get_nickname(participant_id: str) -> str | None:
    db = get_db()
    row = db.execute(
        "SELECT nickname FROM participant_nicknames WHERE participant_id = ?", (participant_id,)
    ).fetchone()
    return row["nickname"] if row else None


def display_identity(participant_id: str) -> str:
    """Nickname-first with participant_id as a small parenthetical --
    the shared display format used both in a participant's own view
    (see base.html) and on the trainer dashboard's Participant
    Leaderboard (see app/trainer.py). Falls back to the participant_id
    alone (no parenthetical -- nothing to disambiguate from) if no
    nickname has been set yet."""
    nickname = get_nickname(participant_id)
    short_id = short_participant_id(participant_id)
    return f"{nickname} ({short_id})" if nickname else short_id


def set_nickname(participant_id: str, requested: str) -> str:
    """Sets participant_id's nickname to `requested`, silently
    disambiguating on collision with another participant's existing
    nickname (per the design decision: no enforced uniqueness, no
    rejection -- this is a display convenience, not an identity system).
    Returns the nickname actually stored, which may differ from
    `requested` if a short numeric suffix had to be appended. Setting
    your own nickname again (to a value already yours) is no-op-safe:
    it doesn't collide with itself."""
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
    """Asked on first visit (see base.html's nickname prompt), but not
    gated to only-first-visit server-side -- a participant can still
    change their nickname later by resubmitting, same as they could
    dismiss the prompt and never set one at all. Tied purely to the
    wg_pid cookie, independent of login state (this route itself
    doesn't require login), matching how participant identity works
    everywhere else in this app."""
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


def participant_standings():
    """Participant progress standings, most flags first (ties broken by who
    got there first) -- shared by the instructor dashboard's leaderboard and
    the standalone /participants console. Built from flag_redemptions, so a
    participant appears once they've redeemed at least one flag."""
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

