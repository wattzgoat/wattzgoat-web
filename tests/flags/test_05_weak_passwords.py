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
