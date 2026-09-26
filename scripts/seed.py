#!/usr/bin/env python3
"""Seeds a fresh WattzGOAT database with fixture data.

Usage: python scripts/seed.py --out /app/data/app.db
Refuses to touch a database that already exists -- the entrypoint script
relies on that to decide whether seeding is needed.
"""
import argparse
import hashlib
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
from fixtures import (
    ADMINS, ALARM_SEEDS, BILL_AMOUNTS, BILL_PERIOD, CUSTOMERS,
    CUSTOMER_CREATED_HOURS_AGO, METER_BALANCES, METER_CODES, METER_NICKNAMES,
    SESSIONID_ACCOUNT, SESSIONID_ACCOUNT_BASELINE_TOKEN, SQLI_BONUS_FLAG_VALUE,
    SQLI_EXERCISE_FLAG_VALUE, SQLI_FLAG_ACCOUNTS, SQLI_TEACH_FLAG_VALUE,
)


def weak_hash(password: str) -> str:
    """Deliberately weak, unsalted hash -- part of the lab, not a bug."""
    return hashlib.md5(password.encode()).hexdigest()


def build(conn: sqlite3.Connection) -> None:
    schema_path = os.path.join(os.path.dirname(__file__), "..", "app", "schema.sql")
    with open(schema_path) as f:
        conn.executescript(f.read())

    cur = conn.cursor()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    customer_ids = []
    for (email, password, name, service_addr, billing_addr), hours_ago in zip(CUSTOMERS, CUSTOMER_CREATED_HOURS_AGO):
        created = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO users (email, password_hash, role, name, address_service, address_billing, created_at) "
            "VALUES (?, ?, 'customer', ?, ?, ?, ?)",
            (email, weak_hash(password), name, service_addr, billing_addr, created),
        )
        customer_ids.append(cur.lastrowid)

    for email, password, name in ADMINS:
        cur.execute(
            "INSERT INTO users (email, password_hash, role, name) VALUES (?, ?, 'admin', ?)",
            (email, weak_hash(password), name),
        )

    meter_ids = []
    for owner_id, nickname, meter_code, balance in zip(customer_ids, METER_NICKNAMES, METER_CODES, METER_BALANCES):
        cur.execute(
            "INSERT INTO meters (meter_code, user_id, nickname, status, balance) "
            "VALUES (?, ?, ?, 'connected', ?)",
            (meter_code, owner_id, nickname, balance),
        )
        meter_ids.append(cur.lastrowid)

    for meter_offset, alarm_type, message in ALARM_SEEDS:
        cur.execute(
            "INSERT INTO alarms (meter_id, type, message) VALUES (?, ?, ?)",
            (meter_ids[meter_offset], alarm_type, message),
        )

    for email, service_name in SQLI_FLAG_ACCOUNTS:
        cur.execute(
            "INSERT INTO users (email, password_hash, role, name) VALUES (?, ?, 'service', ?)",
            (email, weak_hash("not-a-real-login"), service_name),
        )
    svc_meters_id, svc_alarms_id = (
        cur.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
        for email, _ in SQLI_FLAG_ACCOUNTS
    )

    # SQLi teach flag: a fake, otherwise-invisible meter row owned by the
    # meters-sync service account, with the flag as its meter_code -- a
    # UNION targeting `meters` (the table /admin/meters already reads)
    # surfaces it. /admin/meters's own non-injected queries exclude
    # service-owned meters, so this never shows up by ordinary browsing.
    cur.execute(
        "INSERT INTO meters (meter_code, user_id, nickname, status, balance) "
        "VALUES (?, ?, 'internal sync placeholder', 'connected', 0)",
        (SQLI_TEACH_FLAG_VALUE, svc_meters_id),
    )

    # SQLi exercise flag: a second fake, invisible meter (innocuous code,
    # holds no flag itself) purely as an attachment point, plus a fake
    # alarm on it whose message is the flag -- a UNION targeting `alarms`
    # surfaces it, with meter_code displaying as the innocuous decoy, not
    # the teach flag, so the two never appear together in one result set.
    cur.execute(
        "INSERT INTO meters (meter_code, user_id, nickname, status, balance) "
        "VALUES ('MTR-0000', ?, 'internal sync placeholder', 'connected', 0)",
        (svc_alarms_id,),
    )
    decoy_meter_id = cur.lastrowid
    cur.execute(
        "INSERT INTO alarms (meter_id, type, message) VALUES (?, 'sync_check', ?)",
        (decoy_meter_id, SQLI_EXERCISE_FLAG_VALUE),
    )

    # SQL injection bonus (usage search): a fake reading attached to the
    # same decoy meter above. No real customer's own /usage query ever
    # reaches it (it filters by the logged-in customer's own meter_id),
    # so a UNION with no WHERE at all is enough to surface it alongside
    # that customer's real readings.
    cur.execute(
        "INSERT INTO readings (meter_id, reading_kwh, source, recorded_at) VALUES (?, 0, 'correction', ?)",
        (decoy_meter_id, SQLI_BONUS_FLAG_VALUE),
    )

    # Predictable-session-ID exercise account: a customer with no meter,
    # not listed anywhere in class materials. Its session row is planted
    # here (not issued through the normal login flow) specifically so its
    # token is the fixed, known baseline value -- see app/flags.py.
    sid_email, sid_password, sid_name = SESSIONID_ACCOUNT
    cur.execute(
        "INSERT INTO users (email, password_hash, role, name) VALUES (?, ?, 'customer', ?)",
        (sid_email, weak_hash(sid_password), sid_name),
    )
    sid_user_id = cur.lastrowid
    cur.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?, ?)",
        (SESSIONID_ACCOUNT_BASELINE_TOKEN, sid_user_id),
    )

    # Bill rows point at the PDFs generate_bills.py already baked into the
    # image at build time (app/bills/<meter_code>/<period>.pdf) -- nothing
    # to generate here, just record where each customer's bill lives.
    for owner_id, meter_code, amount in zip(customer_ids, METER_CODES, BILL_AMOUNTS):
        cur.execute(
            "INSERT INTO bills (user_id, period, amount, pdf_filename) VALUES (?, ?, ?, ?)",
            (owner_id, BILL_PERIOD, amount, f"{meter_code}/{BILL_PERIOD}.pdf"),
        )

    conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/app/data/app.db")
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
    print(f"Seeded {args.out}")


if __name__ == "__main__":
    main()
