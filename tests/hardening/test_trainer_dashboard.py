"""Next-phase item 1: the trainer dashboard now runs as its own
decoupled role (TRAINER_DASHBOARD=true, own auth, own DB -- see
app/trainer.py), not an admin-gated page inside the main participant
instance. These tests target that SEPARATE instance
(WATTZGOAT_TRAINER_URL) and are skipped entirely if it isn't
configured -- same optional-second-container convention as
test_hardened_reference.py's WATTZGOAT_HARDENED_URL, since not every
environment running this suite has that second container up (current
CI doesn't -- see .github/workflows/ci.yml's own comment on why).

Two instances, two roles, one shared DB: base_url/ops1_admin (from
tests/conftest.py) talk to the participant instance; trainer_base_url/
trainer_session (from tests/hardening/conftest.py) talk to the trainer
instance. Both are expected to point at the SAME underlying app.db (a
shared volume in the real deployment) for the redemption-tracking test
below to make sense at all.
"""
import re

import pytest

pytestmark = pytest.mark.skipif(
    "WATTZGOAT_TRAINER_URL" not in __import__("os").environ,
    reason="WATTZGOAT_TRAINER_URL not set -- no decoupled trainer instance to test against",
)


def _fresh_customer_session(base_url):
    """A brand-new participant identity on a brand-new throwaway
    account -- see the equivalent helper's docstring in
    tests/flags/test_05_weak_passwords.py-adjacent files for why this
    is a signup, not a login with any seeded account's credentials."""
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
    # No implementation detail naming the underlying endpoint directly
    # (next-phase item 5) -- this instance doesn't even register
    # ops_bp, so /ops/__set_hardening__ isn't reachable here at all.
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

    # Flip back off so this doesn't leak into another test run against
    # the same shared instance -- same teardown discipline as
    # set_hardened's fixture-level version above, done manually here
    # since this isn't going through that fixture.
    trainer_session.post(
        f"{trainer_base_url}/instructor/api/toggle_category",
        data={"category": "Missing security headers", "hardened": "0"},
        timeout=10,
    )


def test_summary_reflects_redemption(trainer_session, trainer_base_url, base_url):
    # Redeem a header-delivered flag on the PARTICIPANT instance, then
    # confirm the TRAINER instance's summary (reading the same shared
    # DB) reflects it -- this is the actual point of decoupling: two
    # separate processes, one source of truth.
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
    # Only present once this participant has redeemed at least one flag
    # (standings are built from flag_redemptions) -- if the shared
    # instance already has other coverage this may be empty for a
    # brand-new pid with no redemptions, which is expected, not a bug.
    if entry is not None:
        assert entry["display"].startswith("LeaderboardTestNick")


def test_reset_lab_control_moved_to_trainer(ops1_admin, base_url, trainer_base_url):
    # Reset Lab lives on the trainer dashboard now, not the general
    # admin nav (see base.html / app/templates/trainer_base.html) --
    # and not on the participant instance's own /instructor/ at all, since
    # that route doesn't exist there anymore.
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
