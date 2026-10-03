"""Smoke tests."""
import os
import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")


def test_login_page_loads():
    resp = requests.get(f"{BASE_URL}/login", verify=False, timeout=10)
    assert resp.status_code == 200
    assert "email" in resp.text.lower()


def test_unauthenticated_dashboard_redirects():
    resp = requests.get(f"{BASE_URL}/dashboard", verify=False, timeout=10, allow_redirects=False)
    assert resp.status_code in (302, 303)
