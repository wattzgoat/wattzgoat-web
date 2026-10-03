import secrets

import requests


def test_sessionid_teach_toggle(base_url, set_hardened, login_fn):
    email = f"sessionid-test-{secrets.token_hex(4)}@example.com"
    password = "Str0ngPassw0rd"
    requests.post(f"{base_url}/signup", data={"email": email, "password": password, "name": "Fixture Account ZzQx"}, verify=False, timeout=10)

    session, _ = login_fn(email, password)
    token = session.cookies.get("wgs_session")
    assert token.isdigit()  # vulnerable: sequential, guessable

    set_hardened("SESSIONID_TEACH", True)

    session2, _ = login_fn(email, password)
    token2 = session2.cookies.get("wgs_session")
    assert not token2.isdigit()  # hardened: random hex, unguessable
    assert len(token2) == 48

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
