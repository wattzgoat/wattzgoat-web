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
    cert_dir = os.environ.get("CERT_DIR", "/app/certs")
    ssl_context = (
        os.path.join(cert_dir, "cert.pem"),
        os.path.join(cert_dir, "key.pem"),
    )

    # Next-phase item 1: TRAINER_DASHBOARD=true boots this same image as
    # the decoupled trainer role instead (see app/__init__.py) -- single
    # HTTPS listener on port 5004 (mapped externally to 4600 per the
    # deployment template), no plaintext mirror (that's specific to
    # PLAINTEXT_TEACH/EXERCISE, irrelevant here), and no meter
    # simulators (those write telemetry into a participant instance's
    # own DB on a timer; the trainer role has nothing of its own for
    # them to simulate against).
    if app.config.get("TRAINER_MODE"):
        app.run(host="0.0.0.0", port=5004, ssl_context=ssl_context)
    else:
        threading.Thread(target=_run_plaintext, daemon=True).start()
        start_simulators(app)
        app.run(host="0.0.0.0", port=5000, ssl_context=ssl_context)
