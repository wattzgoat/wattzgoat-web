import base64
import secrets
import time

import requests


def test_privesc_teach_toggle(devon, base_url, set_hardened):
    devon.post(f"{base_url}/admin/meters/2/reconnect", timeout=10)
    resp = devon.post(f"{base_url}/admin/meters/2/disconnect", timeout=10)
    assert "FLAG{" in resp.text
    devon.post(f"{base_url}/admin/meters/2/reconnect", timeout=10)

    set_hardened("PRIVESC_TEACH", True)

    resp = devon.post(f"{base_url}/admin/meters/2/disconnect", timeout=10)
    assert resp.status_code == 403

    set_hardened("PRIVESC_TEACH", False)
    devon.post(f"{base_url}/admin/meters/2/reconnect", timeout=10)


def test_oldtoken_exercise_toggle(base_url, set_hardened):
    # Phase 7: the flag is claimed on ben's own dashboard now, not on
    # this response -- see auth.py's _forged_reset_pending and
    # customer.py:dashboard().
    email = "ben.wood@example.com"
    stale_ts = int(time.time()) - 7200  # 2 hours old
    token = base64.urlsafe_b64encode(f"{email}:{stale_ts}".encode()).decode()
    session = requests.Session()
    session.verify = False
    resp = session.post(f"{base_url}/reset-password", data={"token": token, "password": "oldtok-vuln-pw1"}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    login_resp = session.post(f"{base_url}/login", data={"email": email, "password": "oldtok-vuln-pw1"}, timeout=10)
    assert login_resp.status_code == 200
    assert "FLAG{" in login_resp.text  # redirect to /dashboard followed by default; flag shown there
    session.post(f"{base_url}/logout", timeout=10)

    set_hardened("OLDTOKEN_EXERCISE", True)

    token2 = base64.urlsafe_b64encode(f"{email}:{stale_ts}".encode()).decode()
    resp = requests.post(f"{base_url}/reset-password", data={"token": token2, "password": "oldtok-hard-pw1"}, verify=False, timeout=10)
    assert resp.status_code == 400

    # password from the vulnerable attempt above still logs in -- the
    # hardened attempt never got applied
    resp = requests.post(f"{base_url}/login", data={"email": email, "password": "oldtok-vuln-pw1"}, verify=False, timeout=10)
    assert resp.status_code in (200, 302)


def test_sessionreuse_bonus_toggle(base_url, set_hardened, login_fn):
    session, _ = login_fn("carla.clark@example.com", "carla123")
    captured = session.cookies.get("wgs_session")
    session.post(f"{base_url}/logout", timeout=10)

    replay = requests.Session()
    replay.verify = False
    replay.cookies.set("wgs_session", captured)
    resp = replay.get(f"{base_url}/dashboard", timeout=10)
    assert resp.status_code == 200  # still logged in post-logout, vulnerable

    set_hardened("SESSIONREUSE_BONUS", True)

    session2, _ = login_fn("farid.shaw@example.com", "farid123")
    captured2 = session2.cookies.get("wgs_session")
    session2.post(f"{base_url}/logout", timeout=10)
    replay2 = requests.Session()
    replay2.verify = False
    replay2.cookies.set("wgs_session", captured2)
    resp = replay2.get(f"{base_url}/dashboard", timeout=10, allow_redirects=False)
    assert resp.status_code == 302
    assert "login" in resp.headers.get("Location", "")


def test_pwchange_teach_toggle(base_url, set_hardened):
    email = f"pwchange-{secrets.token_hex(4)}@example.com"
    requests.post(f"{base_url}/signup", data={"email": email, "password": "Str0ngPassw0rd", "name": "Fixture Account ZzQx"}, verify=False, timeout=10)
    session = requests.Session()
    session.verify = False
    session.post(f"{base_url}/login", data={"email": email, "password": "Str0ngPassw0rd"}, timeout=10)

    resp = session.post(f"{base_url}/account/password", data={"new_password": "Str0ngPassw0rd2"}, timeout=10)
    assert "FLAG{" in resp.text  # no current-password field needed, vulnerable

    set_hardened("PWCHANGE_TEACH", True)

    resp = session.post(f"{base_url}/account/password", data={"new_password": "Str0ngPassw0rd3"}, timeout=10)
    assert resp.status_code == 403  # missing current_password

    resp = session.post(
        f"{base_url}/account/password",
        data={"new_password": "Str0ngPassw0rd3", "current_password": "wrong"},
        timeout=10,
    )
    assert resp.status_code == 403  # wrong current_password

    resp = session.post(
        f"{base_url}/account/password",
        data={"new_password": "Str0ngPassw0rd3", "current_password": "Str0ngPassw0rd2"},
        timeout=10,
    )
    assert resp.status_code == 200  # correct current_password accepted
