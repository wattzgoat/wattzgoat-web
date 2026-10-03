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


def _fresh_participant_with_one_flag(base_url, nickname):
    """A brand-new participant who sets a nickname and redeems one flag, so the
    exports have something of ours to show."""
    import secrets

    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", "export" + secrets.token_hex(5))
    email = f"export-test-{secrets.token_hex(4)}@example.com"
    password = "ExportTest!2026"
    s.post(f"{base_url}/signup", data={"email": email, "password": password, "confirm_password": password, "name": "Export Test"}, timeout=10)
    s.post(f"{base_url}/login", data={"email": email, "password": password}, timeout=10)
    assert s.post(f"{base_url}/participant/nickname", data={"nickname": nickname}, timeout=10).status_code == 200
    flag = s.get(f"{base_url}/dashboard", timeout=10).headers.get("X-Lab-Flag")
    assert flag and s.post(f"{base_url}/progress", data={"flag": flag}, timeout=10).status_code == 200
    return s.cookies.get("wg_pid")


@pytest.mark.skipif(PASSWORD is None, reason="WATTZGOAT_STANDALONE_PASSWORD not set")
def test_console_csv_export_requires_sign_in(base_url):
    for path in ("/participants/export/summary.csv", "/participants/export/detail.csv"):
        resp = _get(base_url, path)
        assert resp.status_code in (302, 303)
        assert "text/csv" not in resp.headers.get("Content-Type", "")


@pytest.mark.skipif(PASSWORD is None, reason="WATTZGOAT_STANDALONE_PASSWORD not set")
def test_console_csv_export_contents_and_formula_safety(base_url):
    import csv
    import io

    pid = _fresh_participant_with_one_flag(base_url, "-Spark")
    s = requests.Session()
    s.verify = False
    assert s.post(f"{base_url}/participants/login", data={"password": PASSWORD}, timeout=10).status_code == 200
    assert "Export CSV" in s.get(f"{base_url}/participants/", timeout=10).text

    summary = s.get(f"{base_url}/participants/export/summary.csv", timeout=10)
    assert summary.status_code == 200
    assert summary.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in summary.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(summary.content.decode("utf-8-sig"))))
    assert rows[0] == ["Rank", "Participant ID", "Nickname", "Flags found", "Total flags", "First activity (UTC)", "Last activity (UTC)"]
    mine = [r for r in rows[1:] if r[1] == pid]
    assert len(mine) == 1 and mine[0][3] == "1" and mine[0][4] == "48"
    assert mine[0][2] == "'-Spark"          # a leading minus would otherwise read as a formula

    detail = s.get(f"{base_url}/participants/export/detail.csv", timeout=10)
    assert detail.status_code == 200 and detail.headers["Content-Type"].startswith("text/csv")
    drows = list(csv.reader(io.StringIO(detail.content.decode("utf-8-sig"))))
    assert drows[0] == ["Participant ID", "Nickname", "Flag key", "Category", "Flag name", "Redeemed at (UTC)", "Redeemed by (account)"]
    mine = [r for r in drows[1:] if r[0] == pid]
    assert len(mine) == 1 and mine[0][2] == "HEADERS_TEACH" and mine[0][3] == "Missing security headers"
    assert "FLAG{" not in detail.text and "FLAG{" not in summary.text      # never a flag's value

    for cell in (c for r in rows + drows for c in r):
        assert not cell.startswith(("=", "+", "-", "@")), cell
