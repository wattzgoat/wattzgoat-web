"""Fixtures for Phase 6 hardening-mode tests.

Two distinct things get tested here, against two distinct kinds of
instance:

1. test_toggle_*.py -- run against the SAME instance the main
   tests/flags/ suite targets (WATTZGOAT_BASE_URL). Each test flips one
   flag_key's toggle on via /ops/__set_hardening__, confirms the
   vulnerable behavior is gone AND the real fix is actually in place
   (not just "no flag" -- an escaped payload, a rejected weak password,
   a header that's actually present), then flips it back off so it
   doesn't leak into a later tests/flags/ run against the same instance.

2. test_hardened_reference.py -- run against a SEPARATE, standalone
   instance booted with HARDENING_MODE=all (WATTZGOAT_HARDENED_URL).
   This is the roadmap's "fully-hardened reference instance" -- no
   per-key toggling involved, every check is force-True at the app
   level (see app/hardening.py). Skipped entirely if
   WATTZGOAT_HARDENED_URL isn't set, since not every environment running
   this suite will have a second container up.

Nothing here duplicates tests/conftest.py's login/account fixtures --
pytest already makes that file's session-scoped fixtures (base_url,
ops1_admin, alice, extract_flag_fn, etc.) available to everything under
this directory automatically, since conftest.py files apply to their
whole subtree.
"""
import os

import pytest


@pytest.fixture(scope="session")
def hardened_base_url():
    """The standalone HARDENING_MODE=all instance's URL, or None if not
    configured -- tests using this fixture should skip (not fail) when
    it's None, since this is an optional second instance, not a
    guaranteed part of every environment running this suite."""
    return os.environ.get("WATTZGOAT_HARDENED_URL")


@pytest.fixture()
def set_hardened(base_url, ops1_admin):
    """Yields a function(flag_key, hardened: bool) -> None that POSTs to
    /ops/__set_hardening__ on the main instance, using the same ops1
    admin session tests/flags/ already logs in with. Automatically flips
    every touched key back to vulnerable (False) on teardown, regardless
    of what the test itself last set it to -- tests/flags/ assumes an
    all-vulnerable instance, and this suite may run before or after it
    against the same live instance, so nothing here should leak state
    past its own test function."""
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
