RATELIMIT_TEACH = "FLAG{NIGHT_COURIER}"     # /login, 5+ failed attempts, bare HTML comment
RATELIMIT_EXERCISE = "FLAG{PALE_HORSE}"     # /forgot-password, 5+ submissions, bare HTML comment

# Fake, unseeded emails so these counters can't collide with any account a
# different test actually needs to log into.
RATELIMIT_LOGIN_EMAIL = "ratelimit-login-test@wattzgoat.example"
RATELIMIT_RESET_EMAIL = "ratelimit-reset-test@wattzgoat.example"


def test_ratelimit_teach_login(anon_session, base_url):
    resp = None
    for _ in range(6):
        resp = anon_session.post(
            f"{base_url}/login",
            data={"email": RATELIMIT_LOGIN_EMAIL, "password": "wrong"},
            timeout=10,
        )
    assert resp.status_code == 401
    assert RATELIMIT_TEACH in resp.text


def test_ratelimit_exercise_forgot_password(anon_session, base_url):
    resp = None
    for _ in range(6):
        resp = anon_session.post(
            f"{base_url}/forgot-password",
            data={"email": RATELIMIT_RESET_EMAIL},
            timeout=10,
        )
    assert resp.status_code == 200
    assert RATELIMIT_EXERCISE in resp.text
