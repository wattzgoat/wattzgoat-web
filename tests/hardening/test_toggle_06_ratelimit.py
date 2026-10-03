import re
import secrets

import requests

FLAG_RE = re.compile(r"FLAG\{[A-Z0-9_]+\}")


def test_ratelimit_teach_toggle(base_url, set_hardened):
    email = f"rl-vuln-{secrets.token_hex(4)}@example.com"
    s = requests.Session()
    s.verify = False
    for _ in range(4):
        resp = s.post(f"{base_url}/login", data={"email": email, "password": "wrong"}, timeout=10)
    baseline = set(FLAG_RE.findall(resp.text))
    resp = s.post(f"{base_url}/login", data={"email": email, "password": "wrong"}, timeout=10)
    at5 = set(FLAG_RE.findall(resp.text))
    assert len(at5 - baseline) == 1  # RATELIMIT_TEACH's flag newly appears at the threshold

    set_hardened("RATELIMIT_TEACH", True)

    email2 = f"rl-hard-{secrets.token_hex(4)}@example.com"
    s2 = requests.Session()
    s2.verify = False
    for _ in range(4):
        resp = s2.post(f"{base_url}/login", data={"email": email2, "password": "wrong"}, timeout=10)
    baseline2 = set(FLAG_RE.findall(resp.text))
    resp = s2.post(f"{base_url}/login", data={"email": email2, "password": "wrong"}, timeout=10)
    at5_hard = set(FLAG_RE.findall(resp.text))
    assert len(at5_hard - baseline2) == 0  # no new flag at the threshold when hardened

    resp = s2.post(f"{base_url}/login", data={"email": email2, "password": "wrong"}, timeout=10)
    assert resp.status_code == 429  # real lockout on the 6th attempt


def test_ratelimit_exercise_toggle(base_url, set_hardened):
    email = f"rle-vuln-{secrets.token_hex(4)}@example.com"
    s = requests.Session()
    s.verify = False
    for _ in range(4):
        resp = s.post(f"{base_url}/forgot-password", data={"email": email}, timeout=10)
    baseline = set(FLAG_RE.findall(resp.text))
    resp = s.post(f"{base_url}/forgot-password", data={"email": email}, timeout=10)
    at5 = set(FLAG_RE.findall(resp.text))
    assert len(at5 - baseline) == 1  # RATELIMIT_EXERCISE's flag newly appears at the threshold

    set_hardened("RATELIMIT_EXERCISE", True)

    email2 = f"rle-hard-{secrets.token_hex(4)}@example.com"
    s2 = requests.Session()
    s2.verify = False
    for _ in range(4):
        resp = s2.post(f"{base_url}/forgot-password", data={"email": email2}, timeout=10)
    baseline2 = set(FLAG_RE.findall(resp.text))
    resp = s2.post(f"{base_url}/forgot-password", data={"email": email2}, timeout=10)
    at5_hard = set(FLAG_RE.findall(resp.text))
    assert len(at5_hard - baseline2) == 0  # no new flag at the threshold when hardened

    resp = s2.post(f"{base_url}/forgot-password", data={"email": email2}, timeout=10)
    assert resp.status_code == 429
