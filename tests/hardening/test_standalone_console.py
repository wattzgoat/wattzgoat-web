"""The hidden /participants console (app/standalone.py). Two situations:

- STANDALONE unset/false (the default, and what CI runs): the routes must
  not exist at all.
- WATTZGOAT_STANDALONE_PASSWORD set to the instance's STANDALONE_PASSWORD:
  the console must be locked behind it. Only non-destructive checks run
  here -- the reset actions are exercised by hand, since running them
  would wipe the shared instance the rest of this suite depends on.
"""
import os

import pytest
import requests

PASSWORD = os.environ.get("WATTZGOAT_STANDALONE_PASSWORD")


def _get(base_url, path, **kw):
    return requests.get(f"{base_url}{path}", verify=False, timeout=10, allow_redirects=False, **kw)


@pytest.mark.skipif(PASSWORD is not None, reason="instance has the standalone console enabled")
def test_console_absent_when_not_standalone(base_url):
    assert _get(base_url, "/participants").status_code == 404
    assert _get(base_url, "/participants/api/leaderboard").status_code == 404
    resp = requests.post(f"{base_url}/participants/reset_lab", verify=False, timeout=10, allow_redirects=False)
    assert resp.status_code == 404


@pytest.mark.skipif(PASSWORD is None, reason="WATTZGOAT_STANDALONE_PASSWORD not set")
def test_console_requires_password(base_url):
    page = _get(base_url, "/participants")
    assert page.status_code == 200
    assert "Reset App" not in page.text and 'type="password"' in page.text
    assert _get(base_url, "/participants/api/leaderboard").status_code == 401
    resp = requests.post(f"{base_url}/participants/reset_app", verify=False, timeout=10, allow_redirects=False)
    assert resp.status_code in (302, 303)     # bounced to the sign-in page, nothing reset


@pytest.mark.skipif(PASSWORD is None, reason="WATTZGOAT_STANDALONE_PASSWORD not set")
def test_console_wrong_password_rejected(base_url):
    resp = requests.post(f"{base_url}/participants/login", data={"password": "definitely-wrong"},
                         verify=False, timeout=10, allow_redirects=False)
    assert resp.status_code == 401
    assert "wgp_session" not in resp.cookies


@pytest.mark.skipif(PASSWORD is None, reason="WATTZGOAT_STANDALONE_PASSWORD not set")
def test_console_shows_leaderboard_and_all_resets(base_url):
    s = requests.Session()
    s.verify = False
    resp = s.post(f"{base_url}/participants/login", data={"password": PASSWORD}, timeout=10)
    assert resp.status_code == 200 and "wgp_session" in s.cookies.get_dict()
    assert all(label in resp.text for label in ("Reset Lab", "Reset App", "Reset All Redemptions"))
    api = s.get(f"{base_url}/participants/api/leaderboard", timeout=10)
    assert api.status_code == 200 and "standings" in api.json()
    assert "/participants" not in s.get(f"{base_url}/robots.txt", timeout=10).text
