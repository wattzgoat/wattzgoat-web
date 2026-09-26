import os
import threading

from app import create_app
from app.simulators import start_simulators

app = create_app()


def _run_plaintext() -> None:
    # Same app, same routes, just no TLS -- this is the whole plaintext
    # transmission category: login and /api/telemetry both work here
    # exactly as they do on the HTTPS port, just unencrypted. See the
    # design notes; there's no separate app or endpoint for this anymore.
    app.run(host="0.0.0.0", port=5001)


if __name__ == "__main__":
    threading.Thread(target=_run_plaintext, daemon=True).start()
    start_simulators(app)

    cert_dir = os.environ.get("CERT_DIR", "/app/certs")
    ssl_context = (
        os.path.join(cert_dir, "cert.pem"),
        os.path.join(cert_dir, "key.pem"),
    )
    app.run(host="0.0.0.0", port=5000, ssl_context=ssl_context)
