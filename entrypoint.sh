#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/app/certs}"
DB_PATH="${DB_PATH:-/app/data/app.db}"
SEED_DB_PATH="${SEED_DB_PATH:-/app/data/seed.db}"

mkdir -p "$CERT_DIR"

# Self-signed certificate for INSTANCE_HOST, used by both roles.
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  HOST="${INSTANCE_HOST:-127.0.0.1}"
  echo "Generating self-signed cert for ${HOST}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days 825 \
    -subj "/CN=${HOST}" \
    -addext "subjectAltName=IP:${HOST}"
fi

# TRAINER_DASHBOARD=true runs this image as the instructor dashboard instead of the
# participant app. DB_PATH must point at the participant instance's database;
# TRAINER_DB_PATH is the instructor's own database, seeded on first start.
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

# Seed the database once. The reset actions copy seed.db back over it.
if [ ! -f "$DB_PATH" ]; then
  echo "Seeding database at ${DB_PATH}"
  python scripts/seed.py --out "$DB_PATH"
  cp "$DB_PATH" "$SEED_DB_PATH"
fi

# STANDALONE=true enables the /participants console and needs STANDALONE_PASSWORD.
# HARDENING_MODE=all makes this a fully hardened reference instance.
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
