"""SQLI_BONUS and ERRHANDLING_TEACH -- see the decoupling note in
customer.py:usage(). Both toggles act on the exact same vulnerable line,
but as two independent, layered defenses: SQLI_BONUS parameterizes the
query; ERRHANDLING_TEACH just changes what happens if a syntax error
still occurs. Tested here together since they share one route.
"""


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
    """Hardening SQLI_BONUS alone (parameterized query) also means a
    stray quote can no longer break the query at all -- so
    ERRHANDLING_TEACH's except-block branch simply never triggers,
    which is a DIFFERENT reason for "no flag" than ERRHANDLING_TEACH
    being hardened itself. Both should still show no flag either way."""
    set_hardened("SQLI_BONUS", True)
    resp = alice.get(f"{base_url}/usage", params={"q": "'"}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text
