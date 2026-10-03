"""Shared fixtures for the flag test suite."""
import base64
import json
import os
import re
import secrets
from urllib.parse import urlparse

import pytest
import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")

PARTICIPANT_ID = secrets.token_hex(8)

FLAG_RE = re.compile(r"FLAG\{[A-Z0-9_]+\}")

CUSTOMER_ALICE = ("alice.smith@example.com", "alice123")   # general-purpose customer
CUSTOMER_DEVON = ("devon.reed@example.com", "devon123")     # kept as the IDOR/privesc "attacker" -- never promoted to admin
CUSTOMER_BEN = ("ben.wood@example.com", "ben123")
CUSTOMER_CARLA = ("carla.clark@example.com", "carla123")     # session-reuse test only
CUSTOMER_FARID = ("farid.shaw@example.com", "farid123")
ADMIN_OPS1 = ("ops1@example.com", "changeme")
ADMIN_DEVADMIN = ("devadmin@example.com", "Dev@2024!")


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
    """Base URL of the plaintext (HTTP) listener."""
    override = os.environ.get("WATTZGOAT_PLAINTEXT_URL")
    if override:
        return override
    parsed = urlparse(BASE_URL)
    https_port = parsed.port or 443
    return f"http://{parsed.hostname}:{https_port + 1}"


def _new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False  # self-signed lab cert
    s.cookies.set("wg_pid", PARTICIPANT_ID)
    return s


def extract_flag(text: str) -> str:
    m = FLAG_RE.search(text)
    assert m, f"no FLAG{{...}} pattern found in response text: {text[:300]!r}"
    return m.group(0)


def redeem_flag(session: requests.Session, base_url: str, flag_value: str) -> bool:
    """POST a flag to /progress and report whether it was accepted."""
    resp = session.post(f"{base_url}/progress", data={"flag": flag_value}, timeout=10)
    assert resp.status_code == 200
    return "Correct!" in resp.text or "Already redeemed" in resp.text


def extract_all_flags(text: str) -> list:
    return FLAG_RE.findall(text)


def checklist_status(session: requests.Session, base_url: str, category: str, name: str) -> bool:
    """Whether a given (category, name) row is marked solved on /progress."""
    resp = session.get(f"{base_url}/progress", timeout=10)
    assert resp.status_code == 200
    pattern = re.compile(
        re.escape(category) + r"</td>\s*<td[^>]*>\s*" + re.escape(name) + r"\s*</td>\s*<td[^>]*>\s*<span[^>]*>(solved|locked)</span>",
        re.DOTALL,
    )
    m = pattern.search(resp.text)
    assert m, f"couldn't find a checklist row for category={category!r}, name={name!r}"
    return m.group(1) == "solved"


@pytest.fixture(scope="session")
def extract_all_flags_fn():
    return extract_all_flags


@pytest.fixture(scope="session")
def checklist_status_fn():
    return checklist_status


@pytest.fixture(scope="session")
def extract_flag_fn():
    return extract_flag


@pytest.fixture(scope="session")
def redeem_flag_fn():
    return redeem_flag


@pytest.fixture(scope="session")
def participant_id():
    return PARTICIPANT_ID


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
