# Build stage: compile the Tailwind stylesheet and vendor Chart.js, so the app
# needs no internet access at runtime.
FROM node:20-slim AS assets
WORKDIR /assets
COPY build/tailwind.config.js build/input.css build/fetch-vendor.mjs ./
COPY app/templates ./templates
RUN npm install -D tailwindcss@3 \
    && npx tailwindcss -i ./input.css -o ./dist/tailwind.css --minify \
    && node fetch-vendor.mjs

FROM python:3.12-slim

# openssl creates the self-signed certificate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=assets /assets/dist/tailwind.css ./app/static/css/tailwind.css
COPY --from=assets /assets/dist/chart.umd.min.js ./app/static/vendor/chart.umd.min.js
COPY scripts ./scripts
COPY run.py entrypoint.sh ./
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

# Generate the bill PDFs at build time.
RUN python scripts/generate_bills.py

ENV DB_PATH=/app/data/app.db \
    SEED_DB_PATH=/app/data/seed.db \
    CERT_DIR=/app/certs \
    TRAINER_DB_PATH=/app/trainer_data/trainer.db

# 5000/5001: participant app (HTTPS / HTTP). 5004: instructor dashboard.
EXPOSE 5000 5001 5004

ENTRYPOINT ["./entrypoint.sh"]
