

def test_headers_teach_dashboard(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    flag = resp.headers.get("X-Lab-Flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)


def test_headers_exercise_login(anon_session, alice, base_url, redeem_flag_fn):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    flag = resp.headers.get("X-Lab-Flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)


def test_headers_clickjack_recharge(farid, devon, base_url, extract_flag_fn, redeem_flag_fn):
    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        headers={"Sec-Fetch-Dest": "iframe"},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(farid, base_url, flag)


def test_headers_clickjack_requires_framing(farid, base_url):
    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text
