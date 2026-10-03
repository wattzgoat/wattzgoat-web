"""Guided mode (app/guided.py, app/guidance.py).

It is only ever OFFERED where an operator asked for it, so a default instance
must show nothing, even if a participant forces the cookie on. These run
against the normal test instance. The data checks need the app package
importable (Flask installed) and are skipped otherwise.
"""
import importlib.util
import os
import secrets
import sys

import pytest
import requests

BASE_URL = os.environ.get("WATTZGOAT_BASE_URL", "https://127.0.0.1:5000")


@pytest.mark.skipif(os.environ.get("WATTZGOAT_GUIDED_MODE", "").lower() == "true",
                    reason="this instance was started with guided mode on")
def test_default_instance_does_not_offer_guided_mode():
    s = requests.Session()
    s.verify = False
    s.cookies.set("wg_pid", "guided" + secrets.token_hex(5))
    s.cookies.set("wg_guided", "1")          # forcing the cookie on must make no difference
    for path in ("/login", "/contact", "/signup"):
        page = s.get(f"{BASE_URL}{path}", timeout=10).text
        assert "wg-guided-toggle" not in page, path
        assert "wg-guided-panel" not in page, path


@pytest.mark.skipif(importlib.util.find_spec("flask") is None, reason="Flask not installed here, so the app package can't be imported")
def test_every_flag_is_mapped_and_hints_are_well_formed():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import flags
    from app.guidance import FLAG_PAGE, HINTS

    keys = {key for key, _category, _name in flags.CATALOG}
    assert set(FLAG_PAGE) == keys                       # every flag belongs to a page (or "beyond")
    assert set(HINTS) == keys                           # and every flag has its hints
    for key, hints in HINTS.items():
        assert len(hints) == 2, key                     # a nudge and a technique
        for hint in hints:
            assert hint.strip() and "FLAG{" not in hint, key


@pytest.mark.skipif(importlib.util.find_spec("flask") is None, reason="Flask not installed here, so the app package can't be imported")
def test_every_mapped_page_is_a_real_page():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    os.environ.setdefault("DB_PATH", os.path.join(os.environ.get("TMPDIR", "/tmp"), "guided_pages_test.db"))
    from app import create_app
    from app.guidance import BEYOND, BEYOND_ENDPOINTS, FLAG_PAGE

    endpoints = {rule.endpoint for rule in create_app().url_map.iter_rules()}
    for key, page in FLAG_PAGE.items():
        assert page == BEYOND or page in endpoints, (key, page)
    assert set(BEYOND_ENDPOINTS) <= endpoints


@pytest.mark.skipif(importlib.util.find_spec("flask") is None, reason="Flask not installed here, so the app package can't be imported")
def test_resets_carry_the_guided_setting_over(tmp_path):
    import shutil
    import sqlite3

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import resets
    from app.guidance import GUIDED_META_KEY

    schema = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "schema.sql")
    seed = str(tmp_path / "seed.db")
    live = str(tmp_path / "app.db")
    conn = sqlite3.connect(seed)
    conn.executescript(open(schema, encoding="utf-8").read())
    conn.commit()
    conn.close()
    shutil.copy(seed, live)

    def value():
        c = sqlite3.connect(live)
        row = c.execute("SELECT value FROM lab_meta WHERE key = ?", (GUIDED_META_KEY,)).fetchone()
        c.close()
        return row[0] if row else None

    c = sqlite3.connect(live)
    c.execute("INSERT INTO lab_meta (key, value) VALUES (?, '1')", (GUIDED_META_KEY,))
    c.commit()
    c.close()

    resets.reset_app_state(live, seed)
    assert value() == "1"
    resets.reset_lab_state(live, seed)
    assert value() == "1"


@pytest.mark.skipif(os.environ.get("WATTZGOAT_GUIDED_MODE", "").lower() != "true",
                    reason="WATTZGOAT_GUIDED_MODE not set (needs an instance started with STANDALONE=true and GUIDED_MODE=true)")
def test_guided_bar_on_an_instance_that_offers_it():
    def participant():
        s = requests.Session()
        s.verify = False
        s.cookies.set("wg_pid", "guidedbar" + secrets.token_hex(4))
        email = f"guided-bar-{secrets.token_hex(4)}@example.com"
        password = "GuidedBar!2026"
        s.post(f"{BASE_URL}/signup", data={"name": "Guided", "email": email, "password": password, "confirm_password": password}, timeout=10)
        s.post(f"{BASE_URL}/login", data={"email": email, "password": password}, timeout=10)
        return s

    on = participant()
    on.cookies.set("wg_guided", "1")
    off = participant()

    page = on.get(f"{BASE_URL}/usage", timeout=10).text
    assert 'id="wg-guided-toggle"' in page
    assert "fixed inset-x-0 bottom-0" in page and "<aside" not in page       # docked along the bottom
    assert page.count("data-hint-card=") == 4 and 'id="wg-guided-next"' in page
    assert page.count('<button type="button" data-flag-tab') == 4             # one numbered tab per flag
    assert page.count('<div class="hidden" data-hint-card=') == 3            # one flag's hints at a time
    # Each flag says which flag it is, numbered among ALL the flags on the page.
    assert all(f"Flag {n} of 4" in page for n in (1, 2, 3, 4))
    assert "no hints written yet" not in page                                 # every flag has hints now
    # Hints move with their own buttons, separate from the flag arrows; going back is possible.
    assert "Show next hint" in page and "Previous hint" in page
    assert page.count('<button type="button" data-hint-prev disabled') == 4
    assert 'aria-label="Previous flag"' in page and 'aria-label="Previous hint"' not in page
    # The bar has no Turn off control (the header switch does that).
    assert "Turn off" not in page and "wg-guided-off" not in page

    # Not on for someone who never turned it on, even on the same instance.
    assert "wg-guided-panel" not in off.get(f"{BASE_URL}/usage", timeout=10).text

    # Exercises that don't belong to one page are grouped under "Beyond the browser".
    beyond = on.get(f"{BASE_URL}/contact", timeout=10).text
    assert "Beyond the browser: 0 of 10 found" in beyond
    assert beyond.count("data-hint-card=") == 10 and beyond.count('<button type="button" data-flag-tab') == 10

    # No panel on the Progress page (the switch itself is still there).
    progress = on.get(f"{BASE_URL}/progress", timeout=10).text
    assert "wg-guided-panel" not in progress and 'id="wg-guided-toggle"' in progress
