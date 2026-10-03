"""Fixtures for the hardening tests."""
import os

import pytest
import requests


@pytest.fixture(scope="session")
def hardened_base_url():
    """URL of the fully hardened reference instance, or None if not configured."""
    return os.environ.get("WATTZGOAT_HARDENED_URL")


@pytest.fixture(scope="session")
def trainer_base_url():
    """URL of the instructor instance, or None if not configured."""
    return os.environ.get("WATTZGOAT_TRAINER_URL")


@pytest.fixture(scope="session")
def trainer_session(trainer_base_url):
    """A logged-in session on the instructor dashboard."""
    if not trainer_base_url:
        return None
    email = os.environ.get("TRAINER1_EMAIL")
    password = os.environ.get("TRAINER1_PASSWORD")
    if not email or not password:
        return None
    s = requests.Session()
    s.verify = False
    resp = s.post(f"{trainer_base_url}/instructor/login", data={"email": email, "password": password}, timeout=10)
    assert "wgt_session" in s.cookies.get_dict(), f"trainer login failed: {resp.status_code}"
    return s


@pytest.fixture()
def set_hardened(base_url, ops1_admin):
    """Yield a function that switches a flag between vulnerable and fixed on the main instance."""
    touched = []

    def _set(flag_key: str, hardened: bool) -> None:
        resp = ops1_admin.post(
            f"{base_url}/ops/__set_hardening__",
            data={"flag_key": flag_key, "hardened": "1" if hardened else "0"},
            timeout=10,
        )
        assert resp.status_code == 200, f"failed to set {flag_key}={hardened}: {resp.status_code} {resp.text[:200]}"
        touched.append(flag_key)

    yield _set

    for key in touched:
        ops1_admin.post(
            f"{base_url}/ops/__set_hardening__",
            data={"flag_key": key, "hardened": "0"},
            timeout=10,
        )
