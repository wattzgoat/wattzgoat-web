-- Schema for the instructor database (separate from app.db).

-- Instructor accounts.
CREATE TABLE trainer_accounts (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Instructor sessions.
CREATE TABLE trainer_sessions (
    token TEXT PRIMARY KEY,
    trainer_email TEXT NOT NULL REFERENCES trainer_accounts(email),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    logged_out_at TEXT
);
