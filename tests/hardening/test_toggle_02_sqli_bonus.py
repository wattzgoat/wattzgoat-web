"""Hardening toggles for the usage-search SQL injection and its error handling."""


def test_sqli_bonus_toggle(alice, base_url, set_hardened):
    payload = "zzz' UNION SELECT reading_kwh, source, recorded_at FROM readings--"
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("SQLI_BONUS", True)

    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text


def test_errhandling_teach_toggle(alice, base_url, set_hardened):
    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert "You have an error in your SQL syntax" in resp.text
    assert "FLAG{" in resp.text

    set_hardened("ERRHANDLING_TEACH", True)

    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert resp.status_code == 200
    assert "You have an error in your SQL syntax" not in resp.text
    assert "FLAG{" not in resp.text


def test_errhandling_teach_independent_of_sqli_bonus(alice, base_url, set_hardened):
    """Parameterizing the query also removes the error a stray quote used to cause."""
    set_hardened("SQLI_BONUS", True)
    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text


def test_sqli_boolean_bonus_toggle(alice, base_url, set_hardened):
    payload = "' OR '1'='1' -- "
    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("SQLI_BOOLEAN_BONUS", True)

    resp = alice.get(f"{base_url}/usage", params={"q": payload}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    union_payload = "zzz' UNION SELECT reading_kwh, source, recorded_at FROM readings--"
    resp = alice.get(f"{base_url}/usage", params={"q": union_payload}, timeout=10)
    assert "FLAG{" not in resp.text
