"""
Shared fixtures for the WattzGOAT flag test suite.

IMPORTANT — these tests are NOT independent of each other or of
execution order. This app has one shared SQLite DB per running
instance, no per-test isolation, and several flags are only reachable
by permanently changing state (promoting an account to admin,
resetting a password, disconnecting a meter, inflating a balance).
Rather than resetting the lab between every test (slow, and defeats
the point of testing reset_lab() as its own thing), tests are ordered
to match the instructor guide's own category sequence via numbered
filenames (test_01_*, test_02_*, ...), and account assignments are
chosen deliberately to avoid one test's side effects breaking a later
one's assumptions -- see the comment above each account choice in the
test files themselves.

Because of this, the suite must be run against a freshly-reset (or
freshly-booted) instance, top to bottom, in one pass -- not cherry-
picked or reordered.
"""
import base64
import json
import os
from urllib.parse import urlparse

import pytest
import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")

# Seeded accounts (see scripts/seed.py / the instructor guide's roster).
# Reused deliberately across test files to mirror how a real participant
# session progresses through the categories on one shared instance.
CUSTOMER_ALICE = ("alice.nguyen@example.com", "alice123")   # general-purpose customer
CUSTOMER_DEVON = ("devon.hale@example.com", "devon123")     # kept as the IDOR/privesc "attacker" -- never promoted to admin
CUSTOMER_BEN = ("ben.osei@example.com", "ben123")            # bill-traversal target; password reset in test_09 (not needed as ben elsewhere)
CUSTOMER_CARLA = ("carla.reyes@example.com", "carla123")     # session-reuse test only
CUSTOMER_FARID = ("farid.khan@example.com", "farid123")      # mass-assignment + role-escalation pair (kept off devon on purpose)
ADMIN_OPS1 = ("ops1@wattzgoat.example", "changeme")
ADMIN_DEVADMIN = ("devadmin@wattzgoat.example", "Dev@2024!")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def forge_none_alg_jwt(meter_code: str) -> str:
    """Builds an alg:none device JWT with no signature -- see app/devices.py."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"meter_code": meter_code}).encode())
    return f"{header}.{payload}."


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def plaintext_base_url():
    """Same host, the deliberate unencrypted mirror on port 5001."""
    parsed = urlparse(BASE_URL)
    return f"http://{parsed.hostname}:5001"


def _new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False  # self-signed lab cert
    return s


@pytest.fixture(scope="session")
def forge_none_alg_jwt_fn():
    return forge_none_alg_jwt


@pytest.fixture(scope="function")
def anon_session():
    """A session that never logs in, for tests that need no auth at all."""
    return _new_session()


def _login(base_url, email, password):
    s = _new_session()
    resp = s.post(f"{base_url}/login", data={"email": email, "password": password}, timeout=10)
    assert resp.status_code in (200, 302), f"login as {email} failed unexpectedly: {resp.status_code}"
    assert "wgs_session" in s.cookies.get_dict(), f"login as {email} did not set a session cookie"
    return s, resp


@pytest.fixture(scope="session")
def alice(base_url):
    session, _ = _login(base_url, *CUSTOMER_ALICE)
    return session


@pytest.fixture(scope="session")
def devon(base_url):
    session, _ = _login(base_url, *CUSTOMER_DEVON)
    return session


@pytest.fixture(scope="session")
def farid(base_url):
    session, _ = _login(base_url, *CUSTOMER_FARID)
    return session


@pytest.fixture(scope="session")
def ops1_admin(base_url):
    session, _ = _login(base_url, *ADMIN_OPS1)
    return session


@pytest.fixture(scope="function")
def login_fn(base_url):
    """For tests that need a fresh login of their own (carla, devadmin,
    ben, or re-logins after a password change) rather than a shared
    session-scoped fixture."""
    def _do(email, password):
        return _login(base_url, email, password)
    return _do
