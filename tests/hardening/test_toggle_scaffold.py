"""Hardening tests, one per hardened flag."""


def test_headers_teach_toggle(alice, base_url, set_hardened):
    # Vulnerable: no frame-protection headers, flag present.
    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    assert resp.headers.get("X-Lab-Flag")

    set_hardened("HEADERS_TEACH", True)

    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    assert resp.headers.get("X-Lab-Flag") is None
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors" in resp.headers.get("Content-Security-Policy", "")


def test_headers_exercise_toggle(anon_session, base_url, set_hardened, ops1_admin):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    assert resp.headers.get("X-Lab-Flag")

    set_hardened("HEADERS_EXERCISE", True)

    resp = anon_session.get(f"{base_url}/login", timeout=10)
    assert resp.headers.get("X-Lab-Flag") is None
    assert "max-age" in resp.headers.get("Strict-Transport-Security", "")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_sqli_teach_toggle(ops1_admin, base_url, extract_flag_fn, set_hardened):
    payload = "zzz' UNION SELECT id,meter_code,user_id,nickname,status,balance,created_at,0,0,0 FROM meters--"
    resp = ops1_admin.get(f"{base_url}/admin/meters", params={"q": payload}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("SQLI_TEACH", True)

    resp = ops1_admin.get(f"{base_url}/admin/meters", params={"q": payload}, timeout=10)
    assert resp.status_code == 200  # parameterized query still runs fine, just matches nothing
    assert "FLAG{" not in resp.text


def test_rxss_teach_toggle(alice, base_url, set_hardened):
    marker = "<script>alert(document.cookie)</script>"
    resp = alice.get(f"{base_url}/usage", params={"q": marker}, timeout=10)
    assert marker in resp.text  # rendered raw, unescaped

    set_hardened("RXSS_TEACH", True)

    resp = alice.get(f"{base_url}/usage", params={"q": marker}, timeout=10)
    assert marker not in resp.text
    assert "&lt;script&gt;" in resp.text  # actually escaped, not just stripped


def test_weakpw_teach_toggle(base_url, set_hardened):
    import secrets

    weak_email = f"wgtest-{secrets.token_hex(4)}@example.com"

    import requests

    r = requests.post(
        f"{base_url}/signup",
        data={"email": weak_email, "password": "abc12345", "name": "Hardening Test"},
        verify=False,
        timeout=10,
    )
    assert "FLAG{" in r.text  # weak-by-policy password accepted, vulnerable branch fires

    set_hardened("WEAKPW_TEACH", True)

    weak_email2 = f"wgtest-{secrets.token_hex(4)}@example.com"
    r = requests.post(
        f"{base_url}/signup",
        data={"email": weak_email2, "password": "abc12345", "name": "Hardening Test"},
        verify=False,
        timeout=10,
    )
    assert "too weak" in r.text
    assert "FLAG{" not in r.text

    # And a policy-compliant password still succeeds (redirected to login).
    strong_email = f"wgtest-{secrets.token_hex(4)}@example.com"
    r = requests.post(
        f"{base_url}/signup",
        data={"email": strong_email, "password": "Str0ngPassw0rd", "name": "Hardening Test"},
        verify=False,
        timeout=10,
        allow_redirects=False,
    )
    assert r.status_code in (302, 303)


def test_weakpw_change_toggle(base_url, set_hardened, login_fn):
    import secrets

    # Fresh account so this test doesn't fight over alice's password with
    # other tests/flags/ runs that also change it.
    email = f"wgtest-{secrets.token_hex(4)}@example.com"
    import requests

    requests.post(
        f"{base_url}/signup",
        data={"email": email, "password": "Str0ngPassw0rd", "name": "Hardening Test"},
        verify=False,
        timeout=10,
    )
    session, _ = login_fn(email, "Str0ngPassw0rd")

    r = session.post(
        f"{base_url}/account/password",
        data={"new_password": "abc12345"},
        headers={"Origin": base_url},
        timeout=10,
    )
    assert "FLAG{" in r.text

    set_hardened("WEAKPW_CHANGE", True)

    r = session.post(
        f"{base_url}/account/password",
        data={"new_password": "stillweak1"},
        headers={"Origin": base_url},
        timeout=10,
    )
    assert "too weak" in r.text
    assert "FLAG{" not in r.text

    # Confirm login with the OLD (weak-but-already-set) password still
    # works -- proves the rejected change never got written.
    session2, _ = login_fn(email, "abc12345")
    assert "wgs_session" in session2.cookies.get_dict()


def test_headers_clickjack_toggle(farid, devon, base_url, set_hardened):
    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        headers={"Sec-Fetch-Dest": "iframe"},
        timeout=10,
    )
    assert "FLAG{" in resp.text

    set_hardened("HEADERS_CLICKJACK", True)

    resp = farid.post(
        f"{base_url}/recharge",
        data={"amount_paid": "10", "target_meter_code": "MTR-1004"},
        headers={"Sec-Fetch-Dest": "iframe"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text
    # target_meter_code is ignored outright once hardened -- own meter credited.
    assert "kWh added" in resp.text
