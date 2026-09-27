def test_errhandling_teach_usage_syntax_error(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_errhandling_exercise_login_enumeration(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "definitely-not-a-real-account@example.com", "password": "whatever"},
        timeout=10,
    )
    assert resp.status_code == 401
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_infoleak_teach_recharge_traceback(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "abc"}, timeout=10)
    assert resp.status_code == 500
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)
