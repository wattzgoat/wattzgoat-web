"""Phase 7: confirm-password fields on signup and account/password.

This is a plain usability check, independent of hardening state -- it's
enforced the same way whether the instance is vulnerable or hardened,
so it lives alongside test_smoke.py rather than under tests/hardening/
(which is specifically for hardened-vs-vulnerable branches) or
tests/flags/ (which is specifically for the 43 vulnerability
instances). Confirm-password is neither.
"""
import os
import secrets

import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")


def test_signup_confirm_password_mismatch_rejected():
    email = f"confirmpw-{secrets.token_hex(4)}@example.com"
    resp = requests.post(
        f"{BASE_URL}/signup",
        data={"email": email, "password": "GoodPass123", "confirm_password": "Different123", "name": "Fixture Account ZzQx"},
        verify=False,
        timeout=10,
    )
    assert "match" in resp.text.lower()

    # account genuinely wasn't created
    login_attempt = requests.post(f"{BASE_URL}/login", data={"email": email, "password": "GoodPass123"}, verify=False, timeout=10)
    assert login_attempt.status_code == 401


def test_signup_confirm_password_match_accepted():
    email = f"confirmpw-{secrets.token_hex(4)}@example.com"
    resp = requests.post(
        f"{BASE_URL}/signup",
        data={"email": email, "password": "GoodPass123", "confirm_password": "GoodPass123", "name": "Fixture Account ZzQx"},
        verify=False,
        timeout=10,
        allow_redirects=False,
    )
    assert resp.status_code in (302, 303)


def test_change_password_confirm_mismatch_rejected():
    email = f"confirmpw-{secrets.token_hex(4)}@example.com"
    requests.post(
        f"{BASE_URL}/signup",
        data={"email": email, "password": "GoodPass123", "confirm_password": "GoodPass123", "name": "Fixture Account ZzQx"},
        verify=False,
        timeout=10,
    )
    session = requests.Session()
    session.verify = False
    session.post(f"{BASE_URL}/login", data={"email": email, "password": "GoodPass123"}, timeout=10)

    resp = session.post(
        f"{BASE_URL}/account/password",
        data={"new_password": "NewPass456", "confirm_new_password": "Mismatch789"},
        timeout=10,
    )
    assert "match" in resp.text.lower()

    # old password still works -- the mismatched change was never applied
    check = requests.post(f"{BASE_URL}/login", data={"email": email, "password": "GoodPass123"}, verify=False, timeout=10)
    assert check.status_code in (200, 302)
