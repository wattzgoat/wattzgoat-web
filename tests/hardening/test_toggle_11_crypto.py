import requests


def test_sessionid_teach_toggle(base_url, set_hardened, login_fn):
    session, _ = login_fn("alice.nguyen@example.com", "alice123")
    token = session.cookies.get("wgs_session")
    assert token.isdigit()  # vulnerable: sequential, guessable

    set_hardened("SESSIONID_TEACH", True)

    session2, _ = login_fn("alice.nguyen@example.com", "alice123")
    token2 = session2.cookies.get("wgs_session")
    assert not token2.isdigit()  # hardened: random hex, unguessable
    assert len(token2) == 48

    # The pre-seeded baseline fixture token still technically resolves
    # to an account (it's planted directly at seed time, independent of
    # issue_session_token()), but no longer awards the flag -- see the
    # gating note in customer.py:dashboard().
    guess = requests.Session()
    guess.verify = False
    guess.cookies.set("wgs_session", "100000")
    resp = guess.get(f"{base_url}/dashboard", timeout=10)
    assert "FLAG{" not in resp.text

    set_hardened("SESSIONID_TEACH", False)


def test_jwt_exercise_toggle(base_url, set_hardened, forge_none_alg_jwt_fn):
    token = forge_none_alg_jwt_fn("MTR-1001")
    resp = requests.post(
        f"{base_url}/api/telemetry",
        json={"reading_kwh": 1.5},
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=10,
    )
    assert resp.status_code == 200
    assert "flag" in resp.json()

    set_hardened("JWT_EXERCISE", True)

    token2 = forge_none_alg_jwt_fn("MTR-1001")
    resp = requests.post(
        f"{base_url}/api/telemetry",
        json={"reading_kwh": 1.5},
        headers={"Authorization": f"Bearer {token2}"},
        verify=False,
        timeout=10,
    )
    assert resp.status_code == 401
