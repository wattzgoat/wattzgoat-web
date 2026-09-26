# Phase 3: flags are personalized per participant_id -- tests extract
# whatever value the app actually returns and confirm /progress accepts
# it, rather than asserting a literal string.


def test_headers_teach_dashboard(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    flag = resp.headers.get("X-Lab-Flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)


def test_headers_exercise_login(anon_session, alice, base_url, redeem_flag_fn):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    flag = resp.headers.get("X-Lab-Flag")
    assert flag
    # Captured anonymously; redeemed via alice's already-logged-in
    # session -- /progress requires auth, but redemption is keyed by
    # participant_id (shared across all sessions in this suite), not by
    # which account submits.
    assert redeem_flag_fn(alice, base_url, flag)
