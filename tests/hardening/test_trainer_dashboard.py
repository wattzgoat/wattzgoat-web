"""Tests for the instructor dashboard."""

import pytest

pytestmark = pytest.mark.skipif(
    "WATTZGOAT_TRAINER_URL" not in __import__("os").environ,
    reason="WATTZGOAT_TRAINER_URL not set -- no decoupled trainer instance to test against",
)


def _fresh_customer_session(base_url):
    """A new participant on a new throwaway account."""
    import secrets

    import requests

    email = f"trainer-summary-test-{secrets.token_hex(4)}@example.com"
    password = "FreshParticipant!2026"
    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", secrets.token_hex(8))
    signup_resp = s.post(
        f"{base_url}/signup",
        data={"email": email, "password": password, "confirm_password": password, "name": "Trainer Summary Test"},
        timeout=10,
    )
    assert signup_resp.status_code in (200, 302)
    login_resp = s.post(f"{base_url}/login", data={"email": email, "password": password}, timeout=10)
    assert login_resp.status_code in (200, 302)
    assert "wgs_session" in s.cookies.get_dict()
    return s


def test_trainer_login_required(trainer_base_url):
    import requests

    resp = requests.get(f"{trainer_base_url}/instructor/", verify=False, timeout=10, allow_redirects=False)
    assert resp.status_code in (302, 303)
    assert resp.headers.get("Location", "").endswith("/instructor/login")


def test_dashboard_loads_with_all_toggles(trainer_session, trainer_base_url):
    resp = trainer_session.get(f"{trainer_base_url}/instructor/", timeout=10)
    assert resp.status_code == 200
    assert resp.text.count("data-flag-key=") == 48
    assert "/ops/__set_hardening__" not in resp.text


def test_ops_endpoints_not_registered_on_trainer_instance(trainer_base_url):
    """The trainer role registers ONLY app/trainer.py's blueprint (see
    app/__init__.py's TRAINER_DASHBOARD branch) -- confirms ops_bp
    genuinely isn't there, not just unlinked from the page."""
    import requests

    resp = requests.post(f"{trainer_base_url}/ops/__set_hardening__", verify=False, timeout=10)
    assert resp.status_code == 404


def test_summary_reflects_category_toggle(trainer_session, trainer_base_url):
    resp = trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data["hardening"]["HEADERS_TEACH"] is False
    assert data["category_hardening"]["Missing security headers"] is False

    toggle = trainer_session.post(
        f"{trainer_base_url}/instructor/api/toggle_category",
        data={"category": "Missing security headers", "hardened": "1"},
        timeout=10,
    )
    assert toggle.status_code == 200
    assert set(toggle.json()["flag_keys"]) == {"HEADERS_TEACH", "HEADERS_EXERCISE", "HEADERS_CLICKJACK"}

    resp = trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10)
    data = resp.json()
    assert data["hardening"]["HEADERS_TEACH"] is True
    assert data["hardening"]["HEADERS_EXERCISE"] is True
    assert data["category_hardening"]["Missing security headers"] is True

    trainer_session.post(
        f"{trainer_base_url}/instructor/api/toggle_category",
        data={"category": "Missing security headers", "hardened": "0"},
        timeout=10,
    )


def test_summary_reflects_redemption(trainer_session, trainer_base_url, base_url):
    fresh = _fresh_customer_session(base_url)
    dash = fresh.get(f"{base_url}/dashboard", timeout=10)
    flag = dash.headers.get("X-Lab-Flag")
    assert flag, "HEADERS_TEACH flag missing -- can't test redemption tracking without it"

    before = trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10).json()
    before_count = before["redemption_counts"].get("HEADERS_TEACH", 0)

    fresh.post(f"{base_url}/progress", data={"flag": flag}, timeout=10)

    after = trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10).json()
    after_count = after["redemption_counts"].get("HEADERS_TEACH", 0)
    assert after_count == before_count + 1
    assert after["total_redemptions"] >= 1
    assert any(p["participant_id"] for p in after["participants"])


def test_participant_leaderboard_nickname_first(trainer_session, trainer_base_url, base_url):
    import secrets

    import requests

    pid = secrets.token_hex(8)
    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", pid)
    s.post(f"{base_url}/login", data={"email": "grace.green@example.com", "password": "grace123"}, timeout=10)
    nick = s.post(f"{base_url}/participant/nickname", data={"nickname": "LeaderboardTestNick"}, timeout=10)
    assert nick.status_code == 200

    page = trainer_session.get(f"{trainer_base_url}/instructor/leaderboard", timeout=10)
    assert page.status_code == 200
    assert "Participant Leaderboard" in page.text

    api = trainer_session.get(f"{trainer_base_url}/instructor/api/leaderboard", timeout=10).json()
    entry = next((row for row in api["standings"] if row["participant_id"] == pid), None)
    if entry is not None:
        assert entry["display"].startswith("LeaderboardTestNick")


def test_reset_lab_control_moved_to_trainer(ops1_admin, base_url, trainer_base_url):
    admin_page = ops1_admin.get(f"{base_url}/admin/", timeout=10)
    assert "Reset Lab" not in admin_page.text

    trainer_page = ops1_admin.get(f"{base_url}/instructor/", timeout=10)
    assert trainer_page.status_code == 404


def test_trainer_csv_export_requires_login_and_works(trainer_session, trainer_base_url):
    import csv
    import io

    import requests

    for path in ("/instructor/export/summary.csv", "/instructor/export/detail.csv"):
        resp = requests.get(f"{trainer_base_url}{path}", verify=False, timeout=10, allow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "text/csv" not in resp.headers.get("Content-Type", "")

    page = trainer_session.get(f"{trainer_base_url}/instructor/leaderboard", timeout=10)
    assert "Export CSV" in page.text

    summary = trainer_session.get(f"{trainer_base_url}/instructor/export/summary.csv", timeout=10)
    assert summary.status_code == 200 and summary.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in summary.headers["Content-Disposition"]
    assert next(csv.reader(io.StringIO(summary.content.decode("utf-8-sig"))))[:4] == ["Rank", "Participant ID", "Nickname", "Flags found"]

    detail = trainer_session.get(f"{trainer_base_url}/instructor/export/detail.csv", timeout=10)
    assert detail.status_code == 200
    assert next(csv.reader(io.StringIO(detail.content.decode("utf-8-sig"))))[:3] == ["Participant ID", "Nickname", "Flag key"]


def test_trainer_guided_mode_switch(trainer_session, trainer_base_url):
    import requests

    anon = requests.post(f"{trainer_base_url}/instructor/api/guided_mode", data={"enabled": "1"}, verify=False,
                         timeout=10, allow_redirects=False)
    assert anon.status_code in (302, 303)

    page = trainer_session.get(f"{trainer_base_url}/instructor/", timeout=10)
    assert 'id="guided-mode-switch"' in page.text

    assert trainer_session.post(f"{trainer_base_url}/instructor/api/guided_mode", data={"enabled": "maybe"}, timeout=10).status_code == 400
    try:
        on = trainer_session.post(f"{trainer_base_url}/instructor/api/guided_mode", data={"enabled": "1"}, timeout=10)
        assert on.status_code == 200 and on.json() == {"enabled": True}
        assert trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10).json()["guided_mode_enabled"] is True
    finally:
        # Off is the default; leave the shared instance the way the rest of the suite expects it.
        trainer_session.post(f"{trainer_base_url}/instructor/api/guided_mode", data={"enabled": "0"}, timeout=10)
    assert trainer_session.get(f"{trainer_base_url}/instructor/api/summary", timeout=10).json()["guided_mode_enabled"] is False
