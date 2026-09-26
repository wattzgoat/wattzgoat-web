-- WattzGOAT schema.

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('customer', 'admin', 'service')),
    name TEXT NOT NULL,
    phone TEXT,
    address_service TEXT,
    address_billing TEXT,
    billing_rate REAL NOT NULL DEFAULT 0.28,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Deliberately homemade instead of Flask's signed cookie session -- see
-- app/auth.py for why (predictable-session-ID teach instance).
-- logged_out_at is written on logout but never consulted when a token is
-- presented -- session-reuse-after-logout flag (see app/auth.py).
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    logged_out_at TEXT
);

-- Password-reset tokens are stateless (base64 of email + a timestamp
-- that's never checked -- see app/auth.py), so there's nothing to store
-- for them.

-- Backs the separate /mail webmail simulation -- a generic table, not
-- reset-specific, so any future "check your inbox" feature (billing
-- alerts, solar-credit confirmations) can reuse it. /mail's "login" is
-- just naming a mailbox with no password check at all (broken
-- authentication exercise instance, alongside the reset token itself).
CREATE TABLE emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_name TEXT NOT NULL DEFAULT 'WattzGOAT',
    sender_email TEXT NOT NULL DEFAULT 'noreply@wattzgoat.example',
    recipient_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE meters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_code TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    nickname TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'connected' CHECK (status IN ('connected', 'disconnected')),
    balance REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Which participant (see app/personalize.py) last set this nickname,
    -- if any. Multiple participants can share the same seeded customer
    -- account, and the nickname itself is genuinely shared state once
    -- set (that's the realistic part of stored XSS worth keeping) -- but
    -- the SXSS_TEACH flag is personalized to whoever actually caused the
    -- current value, not to whoever happens to view the dashboard
    -- afterward. NULL until someone actually changes it via
    -- customer.update_nickname().
    --
    -- Deliberately placed LAST, not inserted between existing columns --
    -- the SQLi teach instance's UNION payload depends on meters.*'s exact
    -- column order (see app/admin.py:meters(), the instructor guide).
    -- Appending keeps that a one-column addition to the payload rather
    -- than a full reshuffle every time this table gains a field.
    nickname_set_by TEXT
);

-- telemetry from the meter simulators + the field-correction IDOR chain
CREATE TABLE readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_id INTEGER NOT NULL REFERENCES meters(id),
    reading_kwh REAL NOT NULL,
    source TEXT NOT NULL DEFAULT 'simulator' CHECK (source IN ('simulator', 'correction')),
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- generated PDF bills -- directory traversal target
CREATE TABLE bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    period TEXT NOT NULL,
    amount REAL NOT NULL,
    pdf_filename TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- prepaid top-up -- business logic teach instance
CREATE TABLE recharges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount_paid REAL NOT NULL,
    units_credited REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- net-metering export credit -- business logic exercise instance
CREATE TABLE solar_exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    exported_kwh REAL NOT NULL,
    credit_amount REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Support tickets -- stored XSS exercise instance
CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    -- Which participant (see lab_meta below / app/personalize.py) authored
    -- this ticket, if any -- NULL for anything not created through the
    -- normal /support flow. Used only to gate the indirect-injection AI
    -- assistant flag to the same participant who planted it, not to
    -- restrict who can view the ticket itself.
    participant_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- admin alarms/events log -- SQL injection exercise instance target
CREATE TABLE alarms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_id INTEGER NOT NULL REFERENCES meters(id),
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- flag redemption tracking for the /progress page -- one row per
-- (flag_key, participant_id) pair, not per flag_key alone, since flag
-- VALUES are now personalized per participant (see app/personalize.py)
-- and only the stable key identifies which of the 37 flags this is.
CREATE TABLE flag_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_key TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    redeemed_by TEXT,
    redeemed_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(flag_key, participant_id)
);

-- Single-row-per-key settings table. Currently holds one row: the random
-- secret personalized flag values are derived from (see
-- app/personalize.py). Regenerated at seed time and again on every
-- /ops/__reset_lab__ run, so flag values also rotate on a lab reset, not
-- just at first boot.
CREATE TABLE lab_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Phase 6: hardening-mode toggle state. One row per flag_key that's ever
-- been flipped to hardened -- a key with NO row here is implicitly
-- vulnerable (see app/hardening.py:is_hardened()'s default), so a
-- freshly seeded DB needs zero rows here and every instance starts fully
-- vulnerable with no seed data required for this table at all.
--
-- Lives in the same app.db that /ops/__reset_lab__ wholesale-swaps back
-- to seed.db's contents (see app/ops.py) -- so a lab reset also resets
-- every hardening toggle back to vulnerable, for free, via the exact
-- same file-swap mechanism that already resets everything else in this
-- DB. No extra reset-lab code needed for this table specifically.
--
-- Not consulted at all when the app is booted with HARDENING_MODE=all
-- (see app/hardening.py) -- that mode is a whole separate, standalone
-- hardened container/port and short-circuits before ever querying this
-- table, so it works even against a DB that predates this table's
-- existence.
CREATE TABLE hardening_state (
    flag_key TEXT PRIMARY KEY,
    hardened INTEGER NOT NULL DEFAULT 0
);
