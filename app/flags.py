
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
BUSLOGIC_NEGATIVE_RECHARGE = "BUSLOGIC_NEGATIVE_RECHARGE"
BUSLOGIC_NEGATIVE_SOLAR = "BUSLOGIC_NEGATIVE_SOLAR"
ERRHANDLING_TEACH = "ERRHANDLING_TEACH"
ERRHANDLING_EXERCISE = "ERRHANDLING_EXERCISE"
CSRF_TEACH = "CSRF_TEACH"
CSRF_EXERCISE = "CSRF_EXERCISE"
FILEUPLOAD_TEACH = "FILEUPLOAD_TEACH"
FILEUPLOAD_EXERCISE = "FILEUPLOAD_EXERCISE"
ACCOUNT_IDOR_BONUS = "ACCOUNT_IDOR_BONUS"
HEADERS_CLICKJACK = "HEADERS_CLICKJACK"
SQLI_BOOLEAN_BONUS = "SQLI_BOOLEAN_BONUS"

# Category 15 -- Bonus: Simulated AI Assistant. See app/assistant.py.
ASSISTANT_SYSPROMPT_LEAK = "ASSISTANT_SYSPROMPT_LEAK"
ASSISTANT_DIRECT_ACTION = "ASSISTANT_DIRECT_ACTION"
ASSISTANT_DIRECT_DATALEAK = "ASSISTANT_DIRECT_DATALEAK"
ASSISTANT_INDIRECT_INJECTION = "ASSISTANT_INDIRECT_INJECTION"
ASSISTANT_OUTPUT_XSS = "ASSISTANT_OUTPUT_XSS"

CATALOG = [
    (HEADERS_TEACH, "Missing security headers", "Dashboard"),
    (HEADERS_EXERCISE, "Missing security headers", "Login page"),
    (HEADERS_CLICKJACK, "Missing security headers", "Recharge"),
    (SQLI_TEACH, "SQL injection", "Meter search"),
    (SQLI_EXERCISE, "SQL injection", "Alarm search"),
    (SQLI_BONUS, "SQL injection", "Usage search"),
    (SQLI_BOOLEAN_BONUS, "SQL injection", "Usage search"),
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
    (ACCOUNT_IDOR_BONUS, "Broken access control", "Account settings"),
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
    (BUSLOGIC_NEGATIVE_RECHARGE, "Business logic flaws", "Recharge amount"),
    (BUSLOGIC_NEGATIVE_SOLAR, "Business logic flaws", "Solar export amount"),
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

assert len(CATALOG) == 48
assert len(VALID_KEYS) == 48, "flag keys must be unique"

REMEDIATION = {
    HEADERS_TEACH: "Set X-Frame-Options / a CSP frame-ancestors directive on every response.",
    HEADERS_EXERCISE: "Add HSTS, X-Content-Type-Options, and a real Content-Security-Policy app-wide.",
    HEADERS_CLICKJACK: "Set X-Frame-Options / frame-ancestors on every page, not just the ones an audit happens to sample.",
    SQLI_TEACH: "Use parameterized queries everywhere -- never interpolate user input into SQL.",
    SQLI_EXERCISE: "Same fix as the meter search -- parameterize, don't concatenate.",
    SQLI_BONUS: "The same raw-interpolation pattern needs fixing everywhere it's reused, not just once.",
    SQLI_BOOLEAN_BONUS: "Parameterize the query -- a boolean-based OR bypass is exactly as fixed by that as a UNION is.",
    RXSS_TEACH: "HTML-escape all user-controlled output; never trust it in a rendered response.",
    RXSS_EXERCISE: "Escape user input even in \"not found\" / error messages -- they're output too.",
    SXSS_TEACH: "Never render stored user input with |safe (or equivalent) -- escape by default.",
    SXSS_EXERCISE: "Admin-facing views need the same output escaping as customer-facing ones.",
    WEAKPW_TEACH: "Enforce a minimum length/complexity policy server-side at signup.",
    WEAKPW_EXERCISE: "Force a password change on first login for default/shared admin credentials.",
    WEAKPW_CHANGE: "Enforce a strong password policy (minimum length, mixed case, numbers) on the change-password form, independent of whatever the signup form currently does.",
    RATELIMIT_TEACH: "Add a lockout or exponential backoff after repeated failed logins.",
    RATELIMIT_EXERCISE: "Rate-limit password-reset requests the same way login attempts should be.",
    DEVADMIN_LEAK: "Remove debug/staging credentials from source before anything ships.",
    FIELDTECH_LOOKUP: "Return only the fields a caller actually needs, not the whole owner record.",
    IDOR_TEACH: "Check that the requested resource actually belongs to the caller before returning it.",
    MASSASSIGN_EXERCISE: "Explicitly allow-list which fields a client can update -- never trust the payload's keys.",
    ROLE_ESCALATION_BONUS: "Never let a client-supplied field set its own privilege level.",
    ACCOUNT_IDOR_BONUS: "Derive which account to update from the authenticated session, never from a client-supplied identifier.",
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
    BUSLOGIC_NEGATIVE_RECHARGE: "Validate lower bounds server-side: reject zero, negative and non-numeric payment amounts before applying them.",
    BUSLOGIC_NEGATIVE_SOLAR: "Reject zero or negative self-reported quantities server-side, not just implausibly large ones.",
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

SESSIONID_ACCOUNT_EMAIL = "fieldrelay@example.com"
SESSIONID_ACCOUNT_BASELINE_TOKEN = "100000"

DEVADMIN_ACCOUNT_EMAIL = "devadmin@example.com"

SQLI_TEACH_SENTINEL = "__WG_SENTINEL_SQLI_TEACH__"
SQLI_EXERCISE_SENTINEL = "__WG_SENTINEL_SQLI_EXERCISE__"
SQLI_BONUS_SENTINEL = "__WG_SENTINEL_SQLI_BONUS__"
