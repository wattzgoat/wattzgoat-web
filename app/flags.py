# The master flag catalog. Each entry is (flag_key, category, name) where
# name is a short 1-2 word location hint -- e.g. "Login page" or "Meter
# search" -- shown on /progress instead of the flag itself.
#
# CHANGED (Phase 3): these constants used to hold the actual displayed
# FLAG{...} string. They now hold a stable KEY -- the constant's own name,
# as a plain string -- and the real, per-participant value is computed at
# request time via personalize.get_flag(key, participant_id). Every
# vulnerable route imports the key the same way it always imported the
# flag, and calls get_flag() at the point it used to just embed the
# constant directly.
#
# ONE EXCEPTION, structural, not an oversight: SQLI_TEACH / SQLI_EXERCISE
# / SQLI_BONUS. A UNION-based injection returns whatever's sitting in the
# table to WHOEVER runs the query -- there's no way to make planted row
# DATA itself differ per requester without breaking how real UNION SQLi
# behaves. Instead, the planted rows now hold a SENTINEL marker (see
# *_SENTINEL below, seeded by scripts/seed.py) rather than a flag string;
# the vulnerable routes detect the sentinel in the query results
# server-side (proof a UNION genuinely succeeded, same rigor as before)
# and THEN compute a personalized flag to display separately, rather than
# the flag ever being the exfiltrated data itself.
#
# TRAVERSAL_TEACH was a second exception (baked into a static PDF at
# Docker image build time) until app/billing.py started regenerating that
# one file at request time instead -- it's a fully ordinary personalized
# flag now, same as everything else in this file.
#
# Every core category (1-14) has a teach and an exercise instance, with
# three named exceptions: Broken authentication carries a third ("bonus")
# instance (session reuse after logout), Broken access control carries a
# third bonus instance (role escalation via mass assignment), and SQL
# injection carries a third bonus instance (usage search). Category 15
# ("Bonus — Simulated AI Assistant") is a standalone set of 5 flags with
# no teach/exercise pairing -- see app/assistant.py.

HEADERS_TEACH = "HEADERS_TEACH"
HEADERS_EXERCISE = "HEADERS_EXERCISE"
SQLI_TEACH = "SQLI_TEACH"
SQLI_EXERCISE = "SQLI_EXERCISE"
SQLI_BONUS = "SQLI_BONUS"
RXSS_TEACH = "RXSS_TEACH"
RXSS_EXERCISE = "RXSS_EXERCISE"
SXSS_TEACH = "SXSS_TEACH"
SXSS_EXERCISE = "SXSS_EXERCISE"
WEAKPW_TEACH = "WEAKPW_TEACH"
WEAKPW_EXERCISE = "WEAKPW_EXERCISE"
WEAKPW_CHANGE = "WEAKPW_CHANGE"
RATELIMIT_TEACH = "RATELIMIT_TEACH"
RATELIMIT_EXERCISE = "RATELIMIT_EXERCISE"
INFOLEAK_TEACH = "INFOLEAK_TEACH"
DEVADMIN_LEAK = "DEVADMIN_LEAK"
FIELDTECH_LOOKUP = "FIELDTECH_LOOKUP"
IDOR_TEACH = "IDOR_TEACH"
MASSASSIGN_EXERCISE = "MASSASSIGN_EXERCISE"
ROLE_ESCALATION_BONUS = "ROLE_ESCALATION_BONUS"
PRIVESC_TEACH = "PRIVESC_TEACH"
OLDTOKEN_EXERCISE = "OLDTOKEN_EXERCISE"
SESSIONREUSE_BONUS = "SESSIONREUSE_BONUS"
PWCHANGE_TEACH = "PWCHANGE_TEACH"
TRAVERSAL_TEACH = "TRAVERSAL_TEACH"
CMDINJECT_EXERCISE = "CMDINJECT_EXERCISE"
SESSIONID_TEACH = "SESSIONID_TEACH"
JWT_EXERCISE = "JWT_EXERCISE"
PLAINTEXT_TEACH = "PLAINTEXT_TEACH"
PLAINTEXT_EXERCISE = "PLAINTEXT_EXERCISE"
BUSLOGIC_TEACH = "BUSLOGIC_TEACH"
BUSLOGIC_EXERCISE = "BUSLOGIC_EXERCISE"
ERRHANDLING_TEACH = "ERRHANDLING_TEACH"
ERRHANDLING_EXERCISE = "ERRHANDLING_EXERCISE"
CSRF_TEACH = "CSRF_TEACH"
CSRF_EXERCISE = "CSRF_EXERCISE"
FILEUPLOAD_TEACH = "FILEUPLOAD_TEACH"
FILEUPLOAD_EXERCISE = "FILEUPLOAD_EXERCISE"

# Category 15 -- Bonus: Simulated AI Assistant. See app/assistant.py.
ASSISTANT_SYSPROMPT_LEAK = "ASSISTANT_SYSPROMPT_LEAK"
ASSISTANT_DIRECT_ACTION = "ASSISTANT_DIRECT_ACTION"
ASSISTANT_DIRECT_DATALEAK = "ASSISTANT_DIRECT_DATALEAK"
ASSISTANT_INDIRECT_INJECTION = "ASSISTANT_INDIRECT_INJECTION"
ASSISTANT_OUTPUT_XSS = "ASSISTANT_OUTPUT_XSS"

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
    (WEAKPW_CHANGE, "Weak passwords", "Change password"),
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
    (PWCHANGE_TEACH, "Broken authentication", "Change password"),
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
    (CSRF_TEACH, "CSRF", "Change password"),
    (CSRF_EXERCISE, "CSRF", "Meter nickname"),
    (FILEUPLOAD_TEACH, "Insecure file upload", "Firmware update"),
    (FILEUPLOAD_EXERCISE, "Insecure file upload", "Firmware update"),
    (ASSISTANT_SYSPROMPT_LEAK, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_DIRECT_ACTION, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_DIRECT_DATALEAK, "Bonus — Simulated AI Assistant", "Chat widget"),
    (ASSISTANT_INDIRECT_INJECTION, "Bonus — Simulated AI Assistant", "Support ticket"),
    (ASSISTANT_OUTPUT_XSS, "Bonus — Simulated AI Assistant", "Chat widget"),
]

VALID_KEYS = {key for key, _, _ in CATALOG}

assert len(CATALOG) == 43
assert len(VALID_KEYS) == 43, "flag keys must be unique"

# One-line remediation note shown on /progress after a correct
# submission -- what a developer would actually do to fix this class of
# bug, not a restatement of the exploit.
REMEDIATION = {
    HEADERS_TEACH: "Set X-Frame-Options / a CSP frame-ancestors directive on every response.",
    HEADERS_EXERCISE: "Add HSTS, X-Content-Type-Options, and a real Content-Security-Policy app-wide.",
    SQLI_TEACH: "Use parameterized queries everywhere -- never interpolate user input into SQL.",
    SQLI_EXERCISE: "Same fix as the meter search -- parameterize, don't concatenate.",
    SQLI_BONUS: "The same raw-interpolation pattern needs fixing everywhere it's reused, not just once.",
    RXSS_TEACH: "HTML-escape all user-controlled output; never trust it in a rendered response.",
    RXSS_EXERCISE: "Escape user input even in \"not found\" / error messages -- they're output too.",
    SXSS_TEACH: "Never render stored user input with |safe (or equivalent) -- escape by default.",
    SXSS_EXERCISE: "Admin-facing views need the same output escaping as customer-facing ones.",
    WEAKPW_TEACH: "Enforce a minimum length/complexity policy server-side at signup.",
    WEAKPW_EXERCISE: "Force a password change on first login for default/shared admin credentials.",
    WEAKPW_CHANGE: "Apply the same password policy to the change-password form as to signup.",
    RATELIMIT_TEACH: "Add a lockout or exponential backoff after repeated failed logins.",
    RATELIMIT_EXERCISE: "Rate-limit password-reset requests the same way login attempts should be.",
    DEVADMIN_LEAK: "Remove debug/staging credentials from source before anything ships.",
    FIELDTECH_LOOKUP: "Return only the fields a caller actually needs, not the whole owner record.",
    IDOR_TEACH: "Check that the requested resource actually belongs to the caller before returning it.",
    MASSASSIGN_EXERCISE: "Explicitly allow-list which fields a client can update -- never trust the payload's keys.",
    ROLE_ESCALATION_BONUS: "Never let a client-supplied field set its own privilege level.",
    PRIVESC_TEACH: "Require the correct role, not just any valid session, on privileged actions.",
    OLDTOKEN_EXERCISE: "Check and enforce a reset token's expiry server-side, not just cosmetically.",
    SESSIONREUSE_BONUS: "Invalidate a session token server-side on logout, not just the browser's cookie.",
    PWCHANGE_TEACH: "Require re-entry of the current password before accepting a new one for a sensitive account action.",
    TRAVERSAL_TEACH: "Resolve and validate the final path stays inside the intended directory before serving it.",
    CMDINJECT_EXERCISE: "Never shell out with unsanitized input -- use a safe API instead of string-built commands.",
    SESSIONID_TEACH: "Use a cryptographically random, unguessable session token.",
    JWT_EXERCISE: "Reject tokens whose header claims alg=none; pin the expected algorithm server-side.",
    PLAINTEXT_TEACH: "Redirect all traffic to HTTPS and disable the plaintext listener entirely.",
    PLAINTEXT_EXERCISE: "Device/API traffic needs TLS just as much as browser traffic does.",
    BUSLOGIC_TEACH: "Recompute credited amounts server-side; never trust a client-supplied total.",
    BUSLOGIC_EXERCISE: "Apply a plausibility cap server-side on any self-reported quantity tied to money.",
    ERRHANDLING_TEACH: "Catch DB errors and return a generic message -- never the raw driver error.",
    ERRHANDLING_EXERCISE: "Use one identical error message for both cases, so login failures don't reveal which part was wrong.",
    INFOLEAK_TEACH: "Never render a raw traceback to the client, even during active development.",
    CSRF_TEACH: "Require a per-session anti-CSRF token on any state-changing request, especially sensitive ones like a password change.",
    CSRF_EXERCISE: "Anti-CSRF tokens belong on every state-changing form, not just the ones that feel high-stakes.",
    FILEUPLOAD_TEACH: "Validate file type, size, and content server-side; never trust the client's claimed type or extension.",
    FILEUPLOAD_EXERCISE: "Generate the stored filename server-side; never use a client-supplied filename to build a file path.",
    ASSISTANT_SYSPROMPT_LEAK: "Treat the system prompt as sensitive; don't let user input cause it to be echoed back.",
    ASSISTANT_DIRECT_ACTION: "Don't let a chat message alone authorize a real action outside the caller's own scope.",
    ASSISTANT_DIRECT_DATALEAK: "Apply the same access-control checks to assistant-mediated data access as to the API directly.",
    ASSISTANT_INDIRECT_INJECTION: "Treat content the assistant reads on someone else's behalf (tickets, etc.) as untrusted input, not instructions.",
    ASSISTANT_OUTPUT_XSS: "Never render assistant output with innerHTML; escape it like any other untrusted string.",
}

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

# --- SQLi sentinel markers -- see the module docstring note above. These
# are what actually get planted in the DB by scripts/seed.py; detecting
# one of these in a query's results (not the marker's literal text) is
# what triggers computing and displaying the real, personalized flag.
# Must match scripts/fixtures.py exactly (duplicated there for the same
# reason the rest of that file's constants are -- scripts/ can't import
# app/). Deliberately NOT formatted like FLAG{...} so they're never
# mistakable for (or acceptable as) a real submission on /progress.
SQLI_TEACH_SENTINEL = "__WG_SENTINEL_SQLI_TEACH__"
SQLI_EXERCISE_SENTINEL = "__WG_SENTINEL_SQLI_EXERCISE__"
SQLI_BONUS_SENTINEL = "__WG_SENTINEL_SQLI_BONUS__"
