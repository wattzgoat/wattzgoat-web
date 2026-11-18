"""Hardening toggle for the login SQL injection."""
import requests

BYPASS = {"email": "ops1@example.com'--", "password": "not-the-password"}


def test_sqli_auth_bypass_toggle(anon_session, base_url, set_hardened, extract_flag_fn):
    resp = anon_session.post(f"{base_url}/login", data=BYPASS, timeout=10)
    bypass_flag = extract_flag_fn(resp.text)

    set_hardened("SQLI_AUTH_BYPASS", True)

    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", anon_session.cookies.get("wg_pid"))
    resp = s.post(f"{base_url}/login", data=BYPASS, timeout=10)
    assert resp.status_code == 401
    assert bypass_flag not in resp.text
    assert "wgs_session" not in s.cookies.get_dict()
