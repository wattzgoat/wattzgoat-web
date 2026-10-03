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
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Set by a successful form login; previous_login_at holds the one before.
    last_login_at TEXT,
    previous_login_at TEXT
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    logged_out_at TEXT
);

-- Backs the /mail webmail simulation.
CREATE TABLE emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_name TEXT NOT NULL DEFAULT 'WattzGOAT',
    sender_email TEXT NOT NULL DEFAULT 'noreply@example.com',
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
    -- The participant who last set the nickname.
    nickname_set_by TEXT
);

-- Meter readings.
CREATE TABLE readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_id INTEGER NOT NULL REFERENCES meters(id),
    reading_kwh REAL NOT NULL,
    source TEXT NOT NULL DEFAULT 'simulator' CHECK (source IN ('simulator', 'correction')),
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Customer bills (PDF files).
CREATE TABLE bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    period TEXT NOT NULL,
    amount REAL NOT NULL,
    pdf_filename TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Prepaid top-ups.
CREATE TABLE recharges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount_paid REAL NOT NULL,
    units_credited REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Solar export credits.
CREATE TABLE solar_exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    exported_kwh REAL NOT NULL,
    credit_amount REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Support tickets.
CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    -- The participant who submitted the ticket.
    participant_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Admin alarms and events.
CREATE TABLE alarms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    meter_id INTEGER NOT NULL REFERENCES meters(id),
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One row per (flag_key, participant_id).
CREATE TABLE flag_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_key TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    redeemed_by TEXT,
    redeemed_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(flag_key, participant_id)
);

-- Key/value settings, such as the flag secret.
CREATE TABLE lab_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Flags switched to hardened; a flag with no row is vulnerable.
CREATE TABLE hardening_state (
    flag_key TEXT PRIMARY KEY,
    hardened INTEGER NOT NULL DEFAULT 0
);

-- Display names participants choose for themselves.
CREATE TABLE participant_nicknames (
    participant_id TEXT PRIMARY KEY,
    nickname TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
