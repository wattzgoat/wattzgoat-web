"""Hardening toggles for the admin alarm search SQL injections."""

BOOLEAN_PAYLOAD = "' OR '1'='1' -- "
UNION_PAYLOAD = "zzz' UNION SELECT id,meter_id,type,message,created_at,0 FROM alarms--"


def test_sqli_boolean_exercise_toggle(ops1_admin, base_url, set_hardened):
    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": BOOLEAN_PAYLOAD}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("SQLI_BOOLEAN_EXERCISE", True)

    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": BOOLEAN_PAYLOAD}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": UNION_PAYLOAD}, timeout=10)
    assert "FLAG{" not in resp.text


def test_sqli_exercise_toggle_also_fixes_boolean(ops1_admin, base_url, set_hardened):
    set_hardened("SQLI_EXERCISE", True)

    for payload in (BOOLEAN_PAYLOAD, UNION_PAYLOAD):
        resp = ops1_admin.get(f"{base_url}/admin/alarms", params={"q": payload}, timeout=10)
        assert resp.status_code == 200
        assert "FLAG{" not in resp.text
