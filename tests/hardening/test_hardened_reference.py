"""Tests against the fully hardened reference instance (skipped unless its URL is set)."""
import secrets
import re

import pytest
import requests

CSRF_TOKEN_RE = re.compile(r'name="csrf_token" value="([a-f0-9]+)"')


pytestmark = pytest.mark.skipif(
    "WATTZGOAT_HARDENED_URL" not in __import__("os").environ,
    reason="WATTZGOAT_HARDENED_URL not set -- no standalone hardened instance to test against",
)


def _login(base_url, email, password):
    s = requests.Session()
    s.verify = False
    resp = s.post(f"{base_url}/login", data={"email": email, "password": password}, timeout=10)
    assert resp.status_code in (200, 302)
    return s


def test_headers_teach_no_flag(hardened_base_url):
    s = _login(hardened_base_url, "alice.smith@example.com", "alice123")
    resp = s.get(f"{hardened_base_url}/dashboard", timeout=10)
    assert resp.headers.get("X-Lab-Flag") is None
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_headers_exercise_no_flag(hardened_base_url):
    resp = requests.get(f"{hardened_base_url}/login", verify=False, timeout=10)
    assert resp.headers.get("X-Lab-Flag") is None
    assert "max-age" in resp.headers.get("Strict-Transport-Security", "")


def test_sqli_teach_no_flag(hardened_base_url):
    s = _login(hardened_base_url, "ops1@example.com", "changeme")
    payload = "zzz' UNION SELECT id,meter_code,user_id,nickname,status,balance,created_at,0,0,0 FROM meters--"
    resp = s.get(f"{hardened_base_url}/admin/meters", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text


def test_rxss_teach_no_flag(hardened_base_url):
    s = _login(hardened_base_url, "alice.smith@example.com", "alice123")
    marker = "<script>alert(1)</script>"
    resp = s.get(f"{hardened_base_url}/usage", params={"q": marker}, timeout=10)
    assert marker not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_weakpw_teach_rejected(hardened_base_url):
    email = f"wgtest-{secrets.token_hex(4)}@example.com"
    resp = requests.post(
        f"{hardened_base_url}/signup",
        data={"email": email, "password": "abc12345", "name": "Hardened Ref Test"},
        verify=False,
        timeout=10,
    )
    assert "too weak" in resp.text
    assert "FLAG{" not in resp.text


def test_weakpw_change_rejected(hardened_base_url):
    email = f"wgtest-{secrets.token_hex(4)}@example.com"
    requests.post(
        f"{hardened_base_url}/signup",
        data={"email": email, "password": "Str0ngPassw0rd", "name": "Hardened Ref Test"},
        verify=False,
        timeout=10,
    )
    s = _login(hardened_base_url, email, "Str0ngPassw0rd")
    account_page = s.get(f"{hardened_base_url}/account", timeout=10)
    m = CSRF_TOKEN_RE.search(account_page.text)
    assert m is not None
    resp = s.post(
        f"{hardened_base_url}/account/password",
        data={"new_password": "abc12345", "csrf_token": m.group(1), "current_password": "Str0ngPassw0rd"},
        headers={"Origin": hardened_base_url},
        timeout=10,
    )
    assert "too weak" in resp.text
    assert "FLAG{" not in resp.text


def test_progress_disabled(hardened_base_url):
    s = _login(hardened_base_url, "alice.smith@example.com", "alice123")
    resp = s.get(f"{hardened_base_url}/progress", timeout=10)
    assert resp.status_code == 404
