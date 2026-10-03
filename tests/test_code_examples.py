"""Code examples (View Code on the Progress page, see app/code_examples.py
and app/progress.py:view_code).

The access rules are the part that matters: a participant gets a flag's code
only after redeeming that flag, enforced on the server. These tests use a
brand-new participant identity (its own participant cookie) so they don't
depend on which flags the rest of the suite has already redeemed.
"""
import importlib.util
import os
import secrets
import sys

import pytest
import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")


def _fresh_participant_session():
    """A brand-new participant on a brand-new account. Not a seeded account: the
    rest of the suite changes some of those passwords partway through."""
    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", "codeex" + secrets.token_hex(5))
    email = f"codeex-{secrets.token_hex(4)}@example.com"
    password = "CodeExamples!2026"
    s.post(f"{BASE_URL}/signup", data={"name": "Code Examples", "email": email, "password": password, "confirm_password": password}, timeout=10)
    resp = s.post(f"{BASE_URL}/login", data={"email": email, "password": password}, timeout=10)
    assert resp.status_code in (200, 302)
    assert "wgs_session" in s.cookies.get_dict()
    return s


def test_code_is_locked_until_the_flag_is_redeemed():
    s = _fresh_participant_session()

    locked = s.get(f"{BASE_URL}/progress/code/HEADERS_TEACH", timeout=10)
    assert locked.status_code == 403
    assert "vulnerable" not in locked.text

    # Earn the flag the normal way: it rides on the dashboard's response headers.
    flag = s.get(f"{BASE_URL}/dashboard", timeout=10).headers.get("X-Lab-Flag")
    assert flag
    assert s.post(f"{BASE_URL}/progress", data={"flag": flag}, timeout=10).status_code == 200

    unlocked = s.get(f"{BASE_URL}/progress/code/HEADERS_TEACH", timeout=10)
    assert unlocked.status_code == 200
    data = unlocked.json()
    assert data["key"] == "HEADERS_TEACH"
    assert [lang["id"] for lang in data["languages"]] == ["python", "javascript", "php"]
    for side in ("vulnerable", "fixed"):
        for lang in ("python", "javascript", "php"):
            assert data[side][lang]["code"].strip()
            assert data[side][lang]["highlight"]


def test_one_participants_redemption_does_not_unlock_another():
    solver = _fresh_participant_session()
    flag = solver.get(f"{BASE_URL}/dashboard", timeout=10).headers.get("X-Lab-Flag")
    solver.post(f"{BASE_URL}/progress", data={"flag": flag}, timeout=10)
    assert solver.get(f"{BASE_URL}/progress/code/HEADERS_TEACH", timeout=10).status_code == 200

    someone_else = _fresh_participant_session()
    assert someone_else.get(f"{BASE_URL}/progress/code/HEADERS_TEACH", timeout=10).status_code == 403


def test_code_endpoint_unknown_flags_are_404():
    s = _fresh_participant_session()
    assert s.get(f"{BASE_URL}/progress/code/NOT_A_REAL_FLAG", timeout=10).status_code == 404
    assert s.get(f"{BASE_URL}/progress/code/", timeout=10).status_code == 404


def test_code_endpoint_requires_login():
    resp = requests.get(f"{BASE_URL}/progress/code/HEADERS_TEACH", verify=False, allow_redirects=False, timeout=10)
    assert resp.status_code in (301, 302, 401)


def test_progress_page_shows_a_code_column():
    s = _fresh_participant_session()
    page = s.get(f"{BASE_URL}/progress", timeout=10).text
    assert "Solve to unlock" in page          # nothing redeemed yet
    assert 'data-view-code="' not in page     # no View code button for a locked flag


@pytest.mark.skipif(importlib.util.find_spec("flask") is None, reason="Flask not installed here, so the app package can't be imported")
def test_every_flag_has_a_complete_example():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import code_examples, flags

    # Every one of the flags has an example, so View code is never "coming soon".
    assert code_examples.example_keys() == flags.VALID_KEYS
    for key in code_examples.example_keys():
        payload = code_examples.example_payload(key)
        assert payload["why"].strip()
        for side in ("vulnerable", "fixed"):
            for lang, _label in code_examples.LANGUAGES:
                snippet = payload[side][lang]
                assert snippet["code"].strip(), (key, side, lang)
                assert snippet["highlight"], (key, side, lang)
                assert max(snippet["highlight"]) <= len(snippet["code"].split("\n")), (key, side, lang)
