DEVADMIN_LEAK = "FLAG{RUSTY_KEYCARD}"        # devadmin's own admin dashboard
FIELDTECH_LOOKUP = "FLAG{OPEN_MANIFEST}"     # /api/field/meter-lookup over-exposure


def test_devadmin_leak(login_fn, base_url):
    session, _ = login_fn("devadmin@wattzgoat.example", "Dev@2024!")
    resp = session.get(f"{base_url}/admin/", timeout=10)
    assert resp.status_code == 200
    assert DEVADMIN_LEAK in resp.text


def test_fieldtech_lookup(anon_session, base_url):
    resp = anon_session.get(f"{base_url}/api/field/meter-lookup", params={"code": "MTR-1002"}, timeout=10)
    assert resp.status_code == 200
    assert FIELDTECH_LOOKUP in resp.text
