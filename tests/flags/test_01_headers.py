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


def test_headers_clickjack_recharge(farid, devon, base_url, extract_flag_fn, redeem_flag_fn):
    # farid's own session submits a recharge that targets devon's meter
    # code (MTR-1004) instead of farid's own -- no ownership check on
    # target_meter_code -- delivered with Sec-Fetch-Dest: iframe, the
    # signal a real browser sends when the request is a navigation
    # inside a frame (what a clickjacking PoC's hidden iframe produces).
    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        headers={"Sec-Fetch-Dest": "iframe"},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(farid, base_url, flag)


def test_headers_clickjack_requires_framing(farid, base_url):
    # Same cross-account retarget, but as a plain top-level submission
    # (no Sec-Fetch-Dest: iframe) -- the underlying IDOR still moves the
    # money (that part isn't conditioned on framing at all), but this is
    # ordinary CSRF/IDOR abuse, not a demonstrated clickjack, so no flag.
    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

