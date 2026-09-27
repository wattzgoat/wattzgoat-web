"""Phase 7: trainer dashboard (/trainer/).

Uses the same set_hardened fixture as tests/hardening/'s other files
(tests/hardening/conftest.py) since the dashboard's own toggle path IS
/ops/__set_hardening__ -- these tests confirm the dashboard's read side
(the summary API) reflects what that endpoint does, not a second,
separate toggle mechanism.
"""
import re
import secrets

import requests


def _fresh_customer_session(base_url):
    """A brand-new participant identity, logged in as Alice.

    Deliberately NOT the shared `alice` fixture. That fixture is
    session-scoped and shares tests/conftest.py's single PARTICIPANT_ID
    across the whole suite run -- by the time tests/hardening/ runs,
    tests/flags/test_01_headers.py has already redeemed HEADERS_TEACH
    with that exact alice/participant_id. Redemption is keyed by
    participant_id (wg_pid), not by account (see app/progress.py and
    the design reference's participant/session split), so re-redeeming
    with the shared session here just returns "Already redeemed" and
    doesn't move the count. This test doesn't need Alice specifically,
    only a genuinely new participant -- see the Design Reference §7.3
    note on preferring fresh throwaway identities over seeded/shared
    ones where a test doesn't specifically need the seeded account's
    role in the story.
    """
    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", secrets.token_hex(8))
    resp = s.post(
        f"{base_url}/login",
        data={"email": "alice.smith@example.com", "password": "alice123"},
        timeout=10,
    )
    assert resp.status_code in (200, 302)
    assert "wgs_session" in s.cookies.get_dict()
    return s


def test_dashboard_loads_with_all_toggles(ops1_admin, base_url):
    resp = ops1_admin.get(f"{base_url}/trainer/", timeout=10)
    assert resp.status_code == 200
    # All 43 catalog entries render a toggle.
    assert resp.text.count("data-flag-key=") == 43


def test_dashboard_requires_admin(alice, base_url):
    resp = alice.get(f"{base_url}/trainer/", timeout=10, allow_redirects=False)
    assert resp.status_code in (302, 303)


def test_summary_reflects_hardening_toggle(ops1_admin, base_url, set_hardened):
    resp = ops1_admin.get(f"{base_url}/trainer/api/summary", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data["hardening"]["SQLI_TEACH"] is False

    set_hardened("SQLI_TEACH", True)

    resp = ops1_admin.get(f"{base_url}/trainer/api/summary", timeout=10)
    data = resp.json()
    assert data["hardening"]["SQLI_TEACH"] is True
    assert data["total_flags"] == 43


def test_summary_reflects_redemption(ops1_admin, base_url):
    # Redeem a header-delivered flag (HEADERS_TEACH, on /dashboard) and
    # confirm it shows up in the trainer summary's counts and roster.
    # Uses a fresh participant (see _fresh_customer_session above), not
    # the shared `alice` fixture, since that one may already have
    # redeemed this exact flag earlier in the suite run.
    fresh = _fresh_customer_session(base_url)
    dash = fresh.get(f"{base_url}/dashboard", timeout=10)
    flag = dash.headers.get("X-Lab-Flag")
    assert flag, "HEADERS_TEACH flag missing -- can't test redemption tracking without it"

    before = ops1_admin.get(f"{base_url}/trainer/api/summary", timeout=10).json()
    before_count = before["redemption_counts"].get("HEADERS_TEACH", 0)

    fresh.post(f"{base_url}/progress", data={"flag": flag}, timeout=10)

    after = ops1_admin.get(f"{base_url}/trainer/api/summary", timeout=10).json()
    after_count = after["redemption_counts"].get("HEADERS_TEACH", 0)
    assert after_count == before_count + 1
    assert after["total_redemptions"] >= 1
    assert any(p["participant_id"] for p in after["participants"])


def test_reset_lab_control_moved_to_trainer(ops1_admin, base_url):
    # Reset Lab lives only on the trainer dashboard now, not the general
    # admin nav (see base.html / app/templates/trainer_dashboard.html).
    admin_page = ops1_admin.get(f"{base_url}/admin/", timeout=10)
    assert "Reset Lab" not in admin_page.text

    trainer_page = ops1_admin.get(f"{base_url}/trainer/", timeout=10)
    assert "Reset Lab" in trainer_page.text
    assert re.search(r'action="[^"]*__reset_lab__"', trainer_page.text)
