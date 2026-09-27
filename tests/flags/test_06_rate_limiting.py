# Fake, unseeded emails so these counters can't collide with any account a
# different test actually needs to log into.
RATELIMIT_LOGIN_EMAIL = "ratelimit-login-test@example.com"
RATELIMIT_RESET_EMAIL = "ratelimit-reset-test@example.com"


def test_ratelimit_teach_login(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = None
    for _ in range(6):
        resp = anon_session.post(
            f"{base_url}/login",
            data={"email": RATELIMIT_LOGIN_EMAIL, "password": "wrong"},
            timeout=10,
        )
    assert resp.status_code == 401
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_ratelimit_exercise_forgot_password(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = None
    for _ in range(6):
        resp = anon_session.post(
            f"{base_url}/forgot-password",
            data={"email": RATELIMIT_RESET_EMAIL},
            timeout=10,
        )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)
