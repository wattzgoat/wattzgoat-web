import time


def test_weakpw_teach_signup(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    # Unique throwaway account each run so repeated CI runs against the
    # same instance (no reset in between) don't collide on a duplicate email.
    email = f"weakpw-test-{int(time.time())}@wattzgoat.example"
    resp = anon_session.post(
        f"{base_url}/signup",
        data={"email": email, "password": "x", "name": "Weak PW Test"},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_weakpw_exercise_admin_default_password(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    resp = ops1_admin.get(f"{base_url}/admin/", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)


def test_weakpw_change(alice, base_url, extract_flag_fn, redeem_flag_fn):
    # Reuses the shared alice fixture's already-authenticated session --
    # changing the account's password this way doesn't invalidate that
    # session's own cookie, and nothing later in the suite re-logs-in as
    # alice by username/password, so this is safe to run mid-suite.
    #
    # Explicit matching Origin header: `requests`, unlike a real browser,
    # never sends Origin automatically, so without this the app's CSRF
    # detection would (correctly, for what it's testing) treat this as
    # cross-origin too and also emit csrf_flag in the same response --
    # muddying this test, which is specifically about WEAKPW_CHANGE.
    resp = alice.post(
        f"{base_url}/account/password",
        data={"new_password": "x"},
        headers={"Origin": base_url},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)
