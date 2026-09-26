RXSS_TEACH = "FLAG{QUIET_CIRCUIT}"     # flag_reflected_xss cookie, set at customer login
RXSS_EXERCISE = "FLAG{VELVET_HAMMER}"  # /forgot-password page <title>


def test_rxss_teach_cookie_and_unescaped_reflection(alice, base_url):
    # The flag itself rides on a cookie set at login (see auth.py) --
    # confirm it's there...
    assert alice.cookies.get("flag_reflected_xss") == RXSS_TEACH

    # ...and confirm the actual vulnerability the exercise is about: the
    # query param comes back on the page unescaped, not HTML-entity-encoded.
    payload = "<script>alert(document.cookie)</script>"
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert payload in resp.text  # unescaped -- would be &lt;script&gt;... if it weren't


def test_rxss_exercise_forgot_password_title(anon_session, base_url):
    payload = "<script>alert(document.title)</script>@test.com"
    resp = anon_session.post(f"{base_url}/forgot-password", data={"email": payload}, timeout=10)
    assert resp.status_code == 200
    assert RXSS_EXERCISE in resp.text
