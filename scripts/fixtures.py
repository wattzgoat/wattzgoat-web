"""Fixture data shared between scripts/seed.py (writes DB rows at container
startup) and scripts/generate_bills.py (writes PDF files at image build
time). Keeping this in one place is what keeps the two in sync -- the PDF
filenames generate_bills.py writes are exactly what seed.py later points
the bills table at.
"""

CUSTOMERS = [
    # (email, password, name, service_address, billing_address)
    # Phase 7: surnames deliberately short, common, easy to type from
    # memory -- the earlier names (Nguyen, Osei, Reyes, Popov, etc.)
    # were realistic but meant every login required copy-pasting the
    # email rather than just typing it, which is friction a live class
    # doesn't need. First names unchanged so every downstream reference
    # (docs, walkthroughs, your own memory of "Ben's account holds the
    # traversal flag") still points at the same person, just a new
    # surname/email.
    ("alice.smith@example.com", "alice123", "Alice Smith", "12 Birch St, Springvale", "12 Birch St, Springvale"),
    ("ben.wood@example.com", "ben123", "Ben Wood", "48 Oak Ave, Riverton", "48 Oak Ave, Riverton"),
    ("carla.clark@example.com", "carla123", "Carla Clark", "7 Maple Ct, Riverton", "PO Box 220, Riverton"),
    ("devon.reed@example.com", "devon123", "Devon Reed", "301 Cedar Rd, Springvale", "301 Cedar Rd, Springvale"),
    ("elena.brown@example.com", "elena123", "Elena Brown", "9 Willow Way, Fairfield", "9 Willow Way, Fairfield"),
    ("farid.shaw@example.com", "farid123", "Farid Shaw", "56 Elm St, Fairfield", "56 Elm St, Fairfield"),
    ("grace.green@example.com", "grace123", "Grace Green", "18 Poplar Ln, Riverton", "18 Poplar Ln, Riverton"),
    ("harun.lee@example.com", "harun123", "Harun Lee", "77 Spruce Dr, Springvale", "77 Spruce Dr, Springvale"),
]

# Weak passwords, never rotated -- "admin accounts never forced off their
# default password" weak-passwords exercise instance.
ADMINS = [
    ("ops1@wattzgoat.example", "changeme", "Priya Shah"),
    ("ops2@wattzgoat.example", "changeme", "Marcus Webb"),
    # Left over from staging and advertised in an HTML comment on the login
    # page. Deliberately NOT "changeme" so it doesn't trip the weak-password
    # flag -- it's a credential-leak finding, not a flag.
    ("devadmin@wattzgoat.example", "Dev@2024!", "Dev Admin"),
]

# One meter per pre-populated customer, same order as CUSTOMERS -- a
# self-signed-up account (via /signup) intentionally gets none. Meter codes
# are deterministic (MTR-1001.. in CUSTOMERS order) since they're also the
# bill directory names generate_bills.py writes at build time.
METER_NICKNAMES = [
    "Garage sub-panel", "Main house meter", "Workshop meter", "Guest suite meter",
    "Basement meter", "Rental unit meter", "Pool house meter", "Barn meter",
]

# Starting balances, same order as CUSTOMERS -- mostly a flat normal
# balance, but Carla (low, <$5) and Elena (negative, this prepaid model
# allows it and deducts it from the next recharge) are seeded on purpose
# so the admin assistant's low/negative-balance skills have something real
# to show from the moment the lab starts, without waiting on other
# exercises to move balances around first.
METER_BALANCES = [25.0, 25.0, 3.50, 25.0, -8.20, 25.0, 25.0, 25.0]

METER_CODES = [f"MTR-{1000 + i}" for i in range(1, len(CUSTOMERS) + 1)]

# Backfilled account-creation ages (hours before seed time), same order as
# CUSTOMERS -- feeds the admin assistant's "users created in the last N
# hours" skill. Deliberately a mix of very old and very recent so the
# query returns a believable, non-empty answer at any N an admin might
# try, from the moment the lab is seeded.
CUSTOMER_CREATED_HOURS_AGO = [4380, 2160, 720, 168, 48, 20, 5, 1]

# A handful of realistic-looking alarm/event rows so /admin/alarms has
# something to search -- (meter offset from the seeded list, type, message).
ALARM_SEEDS = [
    (0, "tamper", "Enclosure tamper switch triggered"),
    (1, "comms_failure", "No check-in for 6 hours"),
    (2, "outage", "Loss of supply detected"),
    (3, "voltage", "Sustained under-voltage on phase A"),
    (4, "tamper", "Magnetic field anomaly detected near meter"),
    (5, "comms_failure", "Firmware heartbeat missed 3 times"),
]

# Two hidden 'service' accounts, not real logins -- their password hashes
# are what the UNION-based SQL injection exercises are really after (weak
# MD5 hashing, discoverable this way as a second path alongside category
# 2's own dedicated instances). Their names are plain and unremarkable on
# purpose: earlier builds put each flag directly in this row's `name`
# field, but since a no-WHERE `UNION SELECT ... FROM users--` returns every
# row in the table regardless of which admin page issued it, that let
# either page's payload return BOTH flags at once. The flags now live
# instead as fake, otherwise-invisible rows in `meters` and `alarms`
# themselves (see seed.py), so following the meters-page technique reaches
# into `meters` and never touches `alarms` at all, and vice versa -- a
# participant who deliberately unions a *different* table than the one
# taught for that page can still cross over, which is fine, real UNION
# SQLi really does let you read any table you can name.
SQLI_FLAG_ACCOUNTS = [
    ("svc-meters@internal.wattzgoat.example", "Meters Sync Service"),
    ("svc-alarms@internal.wattzgoat.example", "Alarms Sync Service"),
]

# Sentinel markers, not flag values -- must match app.flags.SQLI_TEACH_SENTINEL
# / SQLI_EXERCISE_SENTINEL / SQLI_BONUS_SENTINEL exactly (duplicated here
# for the same reason as the rest of this file). Server-side detection of
# one of these in a query's results is what triggers computing and
# displaying a real, personalized flag (see app/admin.py, app/customer.py) --
# the planted row itself no longer carries a flag string, which is what
# makes per-participant SQLi flags possible despite UNION SQLi returning
# identical row data to whoever runs the query (see app/flags.py).
SQLI_TEACH_FLAG_VALUE = "__WG_SENTINEL_SQLI_TEACH__"
SQLI_EXERCISE_FLAG_VALUE = "__WG_SENTINEL_SQLI_EXERCISE__"
SQLI_BONUS_FLAG_VALUE = "__WG_SENTINEL_SQLI_BONUS__"

# Dedicated, undisclosed account for the relocated predictable-session-ID
# flag. No meter, nothing else notable -- must match
# app.flags.SESSIONID_ACCOUNT_EMAIL exactly (duplicated here rather than
# imported since scripts/ and app/ are separate top-level packages, same
# pattern as the flag strings above already being duplicated by hand).
# The password is random and is never meant to be typed in by a
# participant -- this account is only ever reached by guessing/walking its
# session token, never by logging in directly.
SESSIONID_ACCOUNT = ("fieldrelay@wattzgoat.example", "n0t-f0r-hum4n-use-88x2", "Field Relay Unit")
SESSIONID_ACCOUNT_BASELINE_TOKEN = "100000"

# One PDF bill per customer, meter_code in the same order as CUSTOMERS.
# Ben Wood's (index 1, MTR-1002) is the one that carries the directory
# traversal flag -- reachable by requesting his path while logged in as
# anyone else. Period/amount are just fixture flavor.
BILL_PERIOD = "2026-09"
BILL_AMOUNTS = [42.17, 38.90, 51.05, 29.60, 47.33, 33.10, 55.82, 40.25]
TRAVERSAL_FLAG_METER = "MTR-1002"  # Ben Wood
# No longer used by generate_bills.py -- Ben's bill is regenerated at
# request time with a personalized flag instead of one baked in at image
# build time (see app/billing.py, app/customer.py:download_bill()). Left
# here only as a record of the flag category this fixture data supports.
TRAVERSAL_FLAG_VALUE = "FLAG{WRONG_DOOR}"
