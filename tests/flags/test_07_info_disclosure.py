def test_devadmin_leak(login_fn, alice, base_url, extract_flag_fn, redeem_flag_fn):
    session, _ = login_fn("devadmin@wattzgoat.example", "Dev@2024!")
    resp = session.get(f"{base_url}/admin/", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_fieldtech_lookup(anon_session, alice, base_url, redeem_flag_fn):
    resp = anon_session.get(f"{base_url}/api/field/meter-lookup", params={"code": "MTR-1002"}, timeout=10)
    assert resp.status_code == 200
    flag = resp.json().get("flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)
