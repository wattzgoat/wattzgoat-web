import random
import threading
import time

import requests
import urllib3

from .db import get_db
from .devices import issue_device_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TELEMETRY_URL = "https://127.0.0.1:5000/api/telemetry"


def _sample_reading() -> float:
    return round(random.uniform(0.1, 2.5), 2)


def _meter_loop(meter_code: str) -> None:
    token = issue_device_token(meter_code)
    while True:
        try:
            requests.post(
                TELEMETRY_URL,
                json={"reading_kwh": _sample_reading()},
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
                timeout=5,
            )
        except requests.RequestException:
            pass
        time.sleep(random.uniform(20, 40))


def start_simulators(app) -> None:
    """One simulator per meter that actually exists in the DB -- reads the
    seeded meter list itself rather than hardcoding meter codes, so it
    stays correct if the seed data ever changes."""
    with app.app_context():
        meter_codes = [row["meter_code"] for row in get_db().execute("SELECT meter_code FROM meters")]

    for code in meter_codes:
        threading.Thread(target=_meter_loop, args=(code,), daemon=True).start()
