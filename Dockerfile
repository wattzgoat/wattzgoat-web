# Compiles a real, static Tailwind stylesheet from the actual templates
# (replacing the Play CDN <script>, which regenerates CSS client-side via
# JS and requires internet on every page load) and vendors Chart.js, so the
# runtime image below never needs to reach the internet to render correctly
# in an isolated/air-gapped lab environment.
FROM node:20-slim AS assets
WORKDIR /assets
COPY build/tailwind.config.js build/input.css build/fetch-vendor.mjs ./
COPY app/templates ./templates
RUN npm install -D tailwindcss@3 \
    && npx tailwindcss -i ./input.css -o ./dist/tailwind.css --minify \
    && node fetch-vendor.mjs

FROM python:3.12-slim

# openssl CLI for the entrypoint's self-signed cert generation -- not present
# in the slim base image by default.
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

# Bills are static per-customer fixtures -- generated once here, not at
# container startup, since they never differ per instance.
RUN python scripts/generate_bills.py

ENV DB_PATH=/app/data/app.db \
    SEED_DB_PATH=/app/data/seed.db \
    CERT_DIR=/app/certs

EXPOSE 5000 5001

ENTRYPOINT ["./entrypoint.sh"]
