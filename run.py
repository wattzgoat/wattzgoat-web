import os
import threading

from app import create_app
from app.simulators import start_simulators

app = create_app()


def _run_plaintext() -> None:
    app.run(host="0.0.0.0", port=5001)


if __name__ == "__main__":
    cert_dir = os.environ.get("CERT_DIR", "/app/certs")
    ssl_context = (
        os.path.join(cert_dir, "cert.pem"),
        os.path.join(cert_dir, "key.pem"),
    )

    if app.config.get("TRAINER_MODE"):
        app.run(host="0.0.0.0", port=5004, ssl_context=ssl_context)
    else:
        threading.Thread(target=_run_plaintext, daemon=True).start()
        start_simulators(app)
        app.run(host="0.0.0.0", port=5000, ssl_context=ssl_context)
