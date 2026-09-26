"""
Smoke test scaffold for CI.

This is intentionally minimal -- it just proves the pipeline (build image,
boot container, run tests against it, tear down) actually works end to
end. The real per-flag test suite (one test per flag instance, asserting
the exact exploit steps from the instructor guide still work) is planned
as its own piece of work, not included here yet.

WATTZGOAT_BASE_URL is set by the CI workflow to point at the container
it just started (self-signed cert -- verify=False is expected here).
"""
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
