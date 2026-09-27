import requests


def test_devadmin_leak_toggle(base_url, set_hardened, login_fn):
    resp = requests.get(f"{base_url}/login", verify=False, timeout=10)
    assert "Dev@2024!" in resp.text

    set_hardened("DEVADMIN_LEAK", True)

    resp = requests.get(f"{base_url}/login", verify=False, timeout=10)
    assert "Dev@2024!" not in resp.text

    devadmin, _ = login_fn("devadmin@example.com", "Dev@2024!")
    resp = devadmin.get(f"{base_url}/admin/", timeout=10)
    assert "FLAG{" not in resp.text


def test_fieldtech_lookup_toggle(base_url, set_hardened):
    resp = requests.get(f"{base_url}/api/field/meter-lookup", params={"code": "MTR-1002"}, verify=False, timeout=10)
    data = resp.json()
    assert "owner" in data
    assert "flag" in data

    set_hardened("FIELDTECH_LOOKUP", True)

    resp = requests.get(f"{base_url}/api/field/meter-lookup", params={"code": "MTR-1002"}, verify=False, timeout=10)
    data = resp.json()
    assert "owner" not in data
    assert "flag" not in data
    # still a working tool for its actual purpose
    assert data.get("meter_code") == "MTR-1002"
    assert "install_address" in data
