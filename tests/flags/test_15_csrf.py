import re

NICKNAME_ACTION_RE = re.compile(r"/meters/(\d+)/nickname")


def _own_meter_id(session, base_url):
    resp = session.get(f"{base_url}/dashboard", timeout=10)
    m = NICKNAME_ACTION_RE.search(resp.text)
    assert m, "couldn't find a meter nickname form on the dashboard"
    return m.group(1)


def test_csrf_teach(alice, base_url, extract_all_flags_fn, redeem_flag_fn, checklist_status_fn):
    resp = alice.post(
        f"{base_url}/account/password",
        data={"new_password": "AnotherStr0ngPassword!2026"},
        headers={"Origin": "https://evil.example.com"},
        timeout=10,
    )
    assert resp.status_code == 200
    for flag in extract_all_flags_fn(resp.text):
        redeem_flag_fn(alice, base_url, flag)
    assert checklist_status_fn(alice, base_url, "CSRF", "Change password")


def test_csrf_exercise(alice, base_url, redeem_flag_fn, checklist_status_fn):
    meter_id = _own_meter_id(alice, base_url)
    resp = alice.post(
        f"{base_url}/meters/{meter_id}/nickname",
        data={"nickname": "CSRF exercise test"},
        headers={"Origin": "null"},  # matches a local file:// PoC page
        timeout=10,
        allow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    flag = resp.headers.get("X-Lab-Flag")
    assert flag
    redeem_flag_fn(alice, base_url, flag)
    assert checklist_status_fn(alice, base_url, "CSRF", "Meter nickname")
