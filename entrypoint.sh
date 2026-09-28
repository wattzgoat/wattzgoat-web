#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/app/certs}"
DB_PATH="${DB_PATH:-/app/data/app.db}"
SEED_DB_PATH="${SEED_DB_PATH:-/app/data/seed.db}"

mkdir -p "$CERT_DIR"

# Every instance shares one Portainer host IP and differs only by port, so
# the cert only ever needs that one address in its SAN. Set INSTANCE_HOST
# once in the stack template you reuse for every instance. Shared by both
# roles below -- the trainer role (see the branch further down) serves
# HTTPS too, on its own port, and reuses this exact same cert.
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  HOST="${INSTANCE_HOST:-127.0.0.1}"
  echo "Generating self-signed cert for ${HOST}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days 825 \
    -subj "/CN=${HOST}" \
    -addext "subjectAltName=IP:${HOST}"
fi

# Next-phase item 1: TRAINER_DASHBOARD=true boots this same image as the
# decoupled trainer role INSTEAD OF the participant-facing app -- see
# app/__init__.py / run.py. DB_PATH here is expected to point at the
# SAME shared volume/file a target participant instance already seeded
# (this role never seeds or owns that file, only reads/writes into it
# for hardening state, redemptions, and nicknames -- see app/trainer.py).
# TRAINER_DB_PATH is this role's OWN, separate database (trainer
# accounts/sessions, see app/trainer_schema.sql) and IS seeded here, the
# first time this role boots, same "seed once" convention as app.db
# below.
if [ "${TRAINER_DASHBOARD:-}" = "true" ]; then
  TRAINER_DB_PATH="${TRAINER_DB_PATH:-/app/trainer_data/trainer.db}"
  mkdir -p "$(dirname "$TRAINER_DB_PATH")"
  if [ ! -f "$TRAINER_DB_PATH" ]; then
    echo "Seeding trainer-account database at ${TRAINER_DB_PATH}"
    python scripts/seed_trainer.py --out "$TRAINER_DB_PATH"
  fi
  echo "TRAINER_DASHBOARD=true -- this instance is the decoupled trainer dashboard (port 5004), reading/writing DB_PATH=${DB_PATH} as its target participant instance"
  export TRAINER_DB_PATH
  exec python run.py
fi

mkdir -p "$(dirname "$DB_PATH")"

# Seed once; the reset endpoint (Phase 4, and the trainer role's own
# /trainer/reset, see app/trainer.py) copies seed.db back over app.db
# to reset the lab without restarting the container.
if [ ! -f "$DB_PATH" ]; then
  echo "Seeding database at ${DB_PATH}"
  python scripts/seed.py --out "$DB_PATH"
  cp "$DB_PATH" "$SEED_DB_PATH"
fi

# Phase 6: set HARDENING_MODE=all on a container's env to make it a
# standalone, fully-hardened reference instance -- every flag's hardened
# branch forced True at the app level (app/hardening.py), independent of
# hardening_state (never even queried in this mode). Same image, same
# INSTANCE_HOST-style env-var-selected-role pattern as everything else
# here -- no separate Docker image or build step needed. Leave unset (the
# default) for an ordinary participant-facing instance, where hardening is
# instead a live, per-flag DB toggle -- see the trainer dashboard (or, pre-
# decoupling, /ops/__set_hardening__ directly).
# STANDALONE=true enables the hidden /participants console (leaderboard +
# resets) for an instance with no paired instructor container; it needs
# STANDALONE_PASSWORD too (see app/standalone.py). Leave both unset on an
# instance that is paired with an instructor.
if [ "${STANDALONE:-}" = "true" ]; then
  if [ -z "${STANDALONE_PASSWORD:-}" ]; then
    echo "STANDALONE=true but STANDALONE_PASSWORD is not set -- the /participants console will stay disabled"
  else
    echo "STANDALONE=true -- hidden /participants console enabled"
  fi
fi

if [ "${HARDENING_MODE:-}" = "all" ]; then
  echo "HARDENING_MODE=all -- this instance is a standalone hardened reference (see app/hardening.py); /progress is disabled on it"
fi

exec python run.py
