HEADERS_TEACH = "FLAG{SILENT_FALCON}"      # /dashboard response header
HEADERS_EXERCISE = "FLAG{CRIMSON_WIRE}"    # /login response header


def test_headers_teach_dashboard(alice, base_url):
    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    assert resp.headers.get("X-Lab-Flag") == HEADERS_TEACH


def test_headers_exercise_login(anon_session, base_url):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    assert resp.headers.get("X-Lab-Flag") == HEADERS_EXERCISE
