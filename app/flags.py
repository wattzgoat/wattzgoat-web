# The master flag catalog. Each entry is (flag_code, category, name) where
# name is a short 1-2 word location hint -- e.g. "Login page" or "Meter
# search" -- shown on /progress instead of the flag itself. It's meant to
# say roughly *where* to look without naming the technique or giving away
# the payload. Several flags legitimately share a name (a few things live
# on the login page, for instance) -- that's expected, not a bug.
#
# Every core category (1-14) has a teach and an exercise instance, with
# three named exceptions: Broken authentication carries a third ("bonus")
# instance (session reuse after logout), Broken access control carries a
# third bonus instance (role escalation via mass assignment), and SQL
# injection carries a third bonus instance (usage search). Category 15
# ("Bonus — Simulated AI Assistant") is a standalone set of 5 flags with
# no teach/exercise pairing -- see app/assistant.py.
#
# INFOLEAK_TEACH is categorized under "Improper error handling," not
# "Sensitive information disclosure" -- it's really "the app reveals
# internals when something goes wrong", which is what that category
# covers. The old INFOLEAK_EXERCISE (a verbose 404) was removed outright
# rather than recategorized -- the underlying behavior is untouched and
# still worth noticing, it just no longer carries a flag.
# "Sensitive information disclosure" is now DEVADMIN_LEAK and
# FIELDTECH_LOOKUP instead, which fit the category's classic meaning
# (things exposed regardless of error state) better.
#
# Flag CONTENT is intentionally themed (spy/ops-style two-word codenames)
# and unrelated to the vulnerability it represents -- the old scheme
# (FLAG{sqli_admin_meters}, etc.) spelled out the technique, which made
# flags guessable without doing the exercise. Read the codename, not the
# constant name, if you're trying to guess a flag: they're deliberately
# decoupled.
#
# Named constants below (HEADERS_TEACH, SQLI_TEACH, etc.) are what the
# actual vulnerable routes import and plant -- importing the constant
# instead of retyping the string means a typo can't silently create a
# flag that never validates.

HEADERS_TEACH = "FLAG{SILENT_FALCON}"
HEADERS_EXERCISE = "FLAG{CRIMSON_WIRE}"
SQLI_TEACH = "FLAG{IRON_SENTINEL}"
SQLI_EXERCISE = "FLAG{OBSIDIAN_RAVEN}"
SQLI_BONUS = "FLAG{COLD_TRAIL}"
RXSS_TEACH = "FLAG{QUIET_CIRCUIT}"
RXSS_EXERCISE = "FLAG{VELVET_HAMMER}"
SXSS_TEACH = "FLAG{HUSHED_STORM}"
SXSS_EXERCISE = "FLAG{AMBER_VIPER}"
WEAKPW_TEACH = "FLAG{HOLLOW_POINT}"
WEAKPW_EXERCISE = "FLAG{SEVERED_LINE}"
RATELIMIT_TEACH = "FLAG{NIGHT_COURIER}"
RATELIMIT_EXERCISE = "FLAG{PALE_HORSE}"
INFOLEAK_TEACH = "FLAG{LOOSE_CANNON}"
DEVADMIN_LEAK = "FLAG{RUSTY_KEYCARD}"
FIELDTECH_LOOKUP = "FLAG{OPEN_MANIFEST}"
IDOR_TEACH = "FLAG{SHADOW_LEDGER}"
MASSASSIGN_EXERCISE = "FLAG{COPPER_KEY}"
ROLE_ESCALATION_BONUS = "FLAG{BORROWED_BADGE}"
PRIVESC_TEACH = "FLAG{BLACKOUT_ECHO}"
OLDTOKEN_EXERCISE = "FLAG{STALE_SIGNAL}"
SESSIONREUSE_BONUS = "FLAG{BACKDOOR_TICKET}"
TRAVERSAL_TEACH = "FLAG{WRONG_DOOR}"
CMDINJECT_EXERCISE = "FLAG{FRACTURED_GLASS}"
SESSIONID_TEACH = "FLAG{COUNTING_SHEEP}"
JWT_EXERCISE = "FLAG{FORGED_PAPERS}"
PLAINTEXT_TEACH = "FLAG{OPEN_CHANNEL}"
PLAINTEXT_EXERCISE = "FLAG{LOUD_WHISPER}"
BUSLOGIC_TEACH = "FLAG{HIDDEN_WALLET}"
BUSLOGIC_EXERCISE = "FLAG{SUNBURST_TALLY}"
ERRHANDLING_TEACH = "FLAG{CRACKED_MASK}"
ERRHANDLING_EXERCISE = "FLAG{TWO_FACED}"

# Category 15 -- Bonus: Simulated AI Assistant. See app/assistant.py for
# the full rule-based chat engine these are planted in. Not a real model --
# disclosed to participants as a simulation, chosen to avoid the CPU/RAM
# cost of self-hosting a real LLM across 3 concurrent instances.
ASSISTANT_SYSPROMPT_LEAK = "FLAG{LOOSE_LIPS}"
ASSISTANT_DIRECT_ACTION = "FLAG{ROGUE_AGENT}"
ASSISTANT_DIRECT_DATALEAK = "FLAG{PILLOW_TALK}"
ASSISTANT_INDIRECT_INJECTION = "FLAG{TROJAN_MEMO}"
ASSISTANT_OUTPUT_XSS = "FLAG{ECHO_CHAMBER}"

CATALOG = [
    (HEADERS_TEACH, "Missing security headers", "Dashboard"),
    (HEADERS_EXERCISE, "Missing security headers", "Login page"),
    (SQLI_TEACH, "SQL injection", "Meter search"),
    (SQLI_EXERCISE, "SQL injection", "Alarm search"),
    (SQLI_BONUS, "SQL injection", "Usage search"),
    (RXSS_TEACH, "Reflected XSS", "Usage search"),
    (RXSS_EXERCISE, "Reflected XSS", "Password reset"),
    (SXSS_TEACH, "Stored XSS", "Meter nickname"),
    (SXSS_EXERCISE, "Stored XSS", "Support ticket"),
    (WEAKPW_TEACH, "Weak passwords", "Signup"),
    (WEAKPW_EXERCISE, "Weak passwords", "Admin account"),
    (RATELIMIT_TEACH, "Lack of rate limiting", "Login"),
    (RATELIMIT_EXERCISE, "Lack of rate limiting", "Password reset"),
    (DEVADMIN_LEAK, "Sensitive information disclosure", "Admin dashboard"),
    (FIELDTECH_LOOKUP, "Sensitive information disclosure", "Meter lookup tool"),
    (IDOR_TEACH, "Broken access control", "Readings API"),
    (MASSASSIGN_EXERCISE, "Broken access control", "Account settings"),
    (ROLE_ESCALATION_BONUS, "Broken access control", "Account settings"),
    (PRIVESC_TEACH, "Broken authentication", "Meter control"),
    (OLDTOKEN_EXERCISE, "Broken authentication", "Password reset"),
    (SESSIONREUSE_BONUS, "Broken authentication", "Logout"),
    (TRAVERSAL_TEACH, "Security misconfiguration", "Bill download"),
    (CMDINJECT_EXERCISE, "Security misconfiguration", "Diagnostics"),
    (SESSIONID_TEACH, "Insecure cryptography", "Another account"),
    (JWT_EXERCISE, "Insecure cryptography", "Telemetry API"),
    (PLAINTEXT_TEACH, "Plaintext transmission", "Login"),
    (PLAINTEXT_EXERCISE, "Plaintext transmission", "Telemetry API"),
    (BUSLOGIC_TEACH, "Business logic flaws", "Recharge"),
    (BUSLOGIC_EXERCISE, "Business logic flaws", "Solar export"),
    (ERRHANDLING_TEACH, "Improper error handling", "Usage search"),
    (ERRHANDLING_EXERCISE, "Improper error handling", "Login"),
    (INFOLEAK_TEACH, "Improper error handling", "Recharge"),
    (ASSISTANT_SYSPROMPT_LEAK, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_DIRECT_ACTION, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_DIRECT_DATALEAK, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_INDIRECT_INJECTION, "Bonus — Simulated AI Assistant", "Support ticket"),
    (ASSISTANT_OUTPUT_XSS, "Bonus — Simulated AI Assistant", "Chat widget"),
]

VALID_FLAGS = {code for code, _, _ in CATALOG}

assert len(CATALOG) == 37
assert len(VALID_FLAGS) == 37, "flag codes must be unique"

# The dedicated, undisclosed account that hosts the relocated predictable-
# session-ID flag (SESSIONID_TEACH). It has no meter and isn't listed in
# any class materials -- it's reached only by guessing/walking a sequential
# wgs_session token, never by logging in directly. Its very first session
# (token "100000", the lowest token this app ever issues) is planted by
# scripts/seed.py and therefore also restored by every /ops/__reset_lab__
# run, so the account's flag-bearing token is always that same known,
# fixed value -- this bounds how long the guessing exercise can take.
SESSIONID_ACCOUNT_EMAIL = "fieldrelay@wattzgoat.example"
SESSIONID_ACCOUNT_BASELINE_TOKEN = "100000"

# The leaked dev-admin account (advertised in an HTML comment on the login
# page) -- DEVADMIN_LEAK is shown on this account's own dashboard once
# logged into, tying the previously-unflagged credential leak to a real,
# flagged payoff.
DEVADMIN_ACCOUNT_EMAIL = "devadmin@wattzgoat.example"
