import re
import secrets

import requests

CSRF_TOKEN_RE = re.compile(r'name="csrf_token" value="([a-f0-9]+)"')


def test_csrf_teach_toggle(base_url, set_hardened):
    email = f"csrf-teach-{secrets.token_hex(4)}@example.com"
    requests.post(f"{base_url}/signup", data={"email": email, "password": "Str0ngPassw0rd", "name": "Fixture Account ZzQx"}, verify=False, timeout=10)
    session = requests.Session()
    session.verify = False
    session.post(f"{base_url}/login", data={"email": email, "password": "Str0ngPassw0rd"}, timeout=10)

    # No Origin header -- requests never sends one automatically, so this
    # looks cross-origin, same as a forged attacker page would.
    resp = session.post(f"{base_url}/account/password", data={"new_password": "Str0ngPassw0rd2"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("CSRF_TEACH", True)

    resp = session.post(f"{base_url}/account/password", data={"new_password": "attacker-set-pw"}, timeout=10)
    assert resp.status_code == 403

    account_page = session.get(f"{base_url}/account", timeout=10)
    m = CSRF_TOKEN_RE.search(account_page.text)
    assert m is not None
    resp = session.post(
        f"{base_url}/account/password",
        data={"new_password": "legit-new-pw1", "csrf_token": m.group(1)},
        timeout=10,
    )
    assert resp.status_code == 200


def test_csrf_exercise_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/meters/1/nickname", data={"nickname": "csrf-vuln-test"}, timeout=10)
    assert resp.headers.get("X-Lab-Flag")

    set_hardened("CSRF_EXERCISE", True)

    resp = alice.post(f"{base_url}/meters/1/nickname", data={"nickname": "attacker-set-nickname"}, timeout=10)
    assert resp.status_code == 403

    dash = alice.get(f"{base_url}/dashboard", timeout=10)
    m = CSRF_TOKEN_RE.search(dash.text)
    assert m is not None
    resp = alice.post(
        f"{base_url}/meters/1/nickname",
        data={"nickname": "legit-rename", "csrf_token": m.group(1)},
        timeout=10,
    )
    assert resp.status_code in (200, 302)
