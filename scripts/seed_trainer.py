#!/usr/bin/env python3
"""Seeds the instructor database with the two instructor accounts."""
import argparse
import os
import sqlite3
import sys

from werkzeug.security import generate_password_hash


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"Missing required environment variable {name} -- refusing to seed "
            "the trainer database with an incomplete or default account. Set "
            "TRAINER1_EMAIL/TRAINER1_PASSWORD/TRAINER2_EMAIL/TRAINER2_PASSWORD "
            "and re-run.",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def build(conn: sqlite3.Connection) -> None:
    schema_path = os.path.join(os.path.dirname(__file__), "..", "app", "trainer_schema.sql")
    with open(schema_path) as f:
        conn.executescript(f.read())

    accounts = [
        (
            _require_env("TRAINER1_EMAIL"),
            _require_env("TRAINER1_PASSWORD"),
            os.environ.get("TRAINER1_NAME", "Instructor 1"),
        ),
        (
            _require_env("TRAINER2_EMAIL"),
            _require_env("TRAINER2_PASSWORD"),
            os.environ.get("TRAINER2_NAME", "Instructor 2"),
        ),
    ]

    cur = conn.cursor()
    for email, password, name in accounts:
        cur.execute(
            "INSERT INTO trainer_accounts (email, password_hash, name) VALUES (?, ?, ?)",
            (email, generate_password_hash(password), name),
        )
    conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/app/trainer_data/trainer.db")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if os.path.exists(args.out):
        print(f"{args.out} already exists, leaving it alone.", file=sys.stderr)
        return

    conn = sqlite3.connect(args.out)
    try:
        build(conn)
    finally:
        conn.close()
    print(f"Seeded trainer database at {args.out}")


if __name__ == "__main__":
    main()
