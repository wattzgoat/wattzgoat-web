import time

WEAKPW_TEACH = "FLAG{HOLLOW_POINT}"      # /signup accepts a 1-char password
WEAKPW_EXERCISE = "FLAG{SEVERED_LINE}"   # ops1 admin still on the seeded default password


def test_weakpw_teach_signup(anon_session, base_url):
    # Unique throwaway account each run so repeated CI runs against the
    # same instance (no reset in between) don't collide on a duplicate email.
    email = f"weakpw-test-{int(time.time())}@wattzgoat.example"
    resp = anon_session.post(
        f"{base_url}/signup",
        data={"email": email, "password": "x", "name": "Weak PW Test"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert WEAKPW_TEACH in resp.text


def test_weakpw_exercise_admin_default_password(ops1_admin, base_url):
    resp = ops1_admin.get(f"{base_url}/admin/", timeout=10)
    assert resp.status_code == 200
    assert WEAKPW_EXERCISE in resp.text
