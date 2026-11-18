"""Readings retention and the usage search's result cap."""
import re

import requests

ALICE_METER = "MTR-1001"
SHOWING = re.compile(r"Showing the first (\d+) of (\d+) matching readings")


def _post_readings(base_url, count, forge_jwt):
    headers = {"Authorization": f"Bearer {forge_jwt(ALICE_METER)}"}
    with requests.Session() as s:
        s.verify = False
        for _ in range(count):
            assert s.post(f"{base_url}/api/telemetry", json={"reading_kwh": 1.0}, headers=headers, timeout=10).status_code == 200


def test_usage_results_are_capped_and_readings_are_trimmed(alice, base_url, forge_none_alg_jwt_fn):
    _post_readings(base_url, 520, forge_none_alg_jwt_fn)

    resp = alice.get(f"{base_url}/usage", params={"q": "20"}, timeout=10)
    assert resp.status_code == 200
    shown, total = map(int, SHOWING.search(resp.text).groups())
    assert shown == 200
    assert 200 < total <= 500
    assert resp.text.count("kWh</span>") == 200
