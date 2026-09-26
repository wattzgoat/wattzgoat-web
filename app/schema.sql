-- WattzGOAT schema.

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('customer', 'admin', 'service')),
    name TEXT NOT NULL,
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
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
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

-- support tickets -- stored XSS exercise instance
CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
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

-- flag redemption tracking for the /progress page
CREATE TABLE flag_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_code TEXT UNIQUE NOT NULL,
    redeemed_by TEXT,
    redeemed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
