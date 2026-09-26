#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/app/certs}"
DB_PATH="${DB_PATH:-/app/data/app.db}"
SEED_DB_PATH="${SEED_DB_PATH:-/app/data/seed.db}"

mkdir -p "$CERT_DIR" "$(dirname "$DB_PATH")"

# Every instance shares one Portainer host IP and differs only by port, so
# the cert only ever needs that one address in its SAN. Set INSTANCE_HOST
# once in the stack template you reuse for every instance.
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  HOST="${INSTANCE_HOST:-127.0.0.1}"
  echo "Generating self-signed cert for ${HOST}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days 825 \
    -subj "/CN=${HOST}" \
    -addext "subjectAltName=IP:${HOST}"
fi

# Seed once; the reset endpoint (Phase 4) copies seed.db back over app.db
# to reset the lab without restarting the container.
if [ ! -f "$DB_PATH" ]; then
  echo "Seeding database at ${DB_PATH}"
  python scripts/seed.py --out "$DB_PATH"
  cp "$DB_PATH" "$SEED_DB_PATH"
fi

exec python run.py
