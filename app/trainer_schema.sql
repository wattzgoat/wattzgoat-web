-- Next-phase item 1: schema for the trainer role's OWN database,
-- entirely separate from app.db (see TRAINER_DB_PATH in
-- app/__init__.py / entrypoint.sh). Deliberately not part of
-- app/schema.sql: trainer_accounts and trainer_sessions must survive
-- an /ops-style reset (see app/trainer.py:reset_lab()), which works by
-- wholesale file-swapping app.db from seed.db -- if these tables lived
-- there, a trainer resetting the lab mid-class would delete their own
-- login out from under themselves. A completely separate file is never
-- touched by that swap, so it doesn't need to be.

CREATE TABLE trainer_accounts (
    email TEXT PRIMARY KEY,
    -- Real, salted, slow hashing (werkzeug.security, scrypt by default)
    -- -- the deliberate opposite of the participant app's own
    -- weak_hash() (unsalted MD5, see app/auth.py). This is the actual
    -- hardened auth item 1 asked for, not a stub.
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Trainer sessions are their own thing too -- a real, unguessable
-- token (see app/trainer_auth.py:issue_trainer_session(), not the
-- participant app's deliberately-sequential issue_session_token()),
-- stored under its own cookie name (wgt_session, not the participant
-- app's wgs_session) so the two can never be confused for each other
-- even if someone somehow had both open in the same browser.
CREATE TABLE trainer_sessions (
    token TEXT PRIMARY KEY,
    trainer_email TEXT NOT NULL REFERENCES trainer_accounts(email),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    logged_out_at TEXT
);
