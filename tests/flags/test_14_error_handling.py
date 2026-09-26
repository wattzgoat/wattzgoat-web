ERRHANDLING_TEACH = "FLAG{CRACKED_MASK}"       # /usage raw DB syntax error
ERRHANDLING_EXERCISE = "FLAG{TWO_FACED}"       # /login, username vs password enumeration (bare comment)
INFOLEAK_TEACH = "FLAG{LOOSE_CANNON}"          # /recharge traceback on bad input


def test_errhandling_teach_usage_syntax_error(alice, base_url):
    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert resp.status_code == 200
    assert ERRHANDLING_TEACH in resp.text


def test_errhandling_exercise_login_enumeration(anon_session, base_url):
    resp = anon_session.post(
        f"{base_url}/login",
        data={"email": "definitely-not-a-real-account@wattzgoat.example", "password": "whatever"},
        timeout=10,
    )
    assert resp.status_code == 401
    assert ERRHANDLING_EXERCISE in resp.text


def test_infoleak_teach_recharge_traceback(alice, base_url):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "abc"}, timeout=10)
    assert resp.status_code == 500
    assert INFOLEAK_TEACH in resp.text
