def test_idor_teach_toggle(devon, alice, base_url, set_hardened):
    resp = devon.get(f"{base_url}/api/meters/2/readings", timeout=10)
    assert "flag" in resp.json()

    set_hardened("IDOR_TEACH", True)

    resp = devon.get(f"{base_url}/api/meters/2/readings", timeout=10)
    assert resp.status_code == 403
    # own-meter access still works
    resp = alice.get(f"{base_url}/api/meters/1/readings", timeout=10)
    assert resp.status_code == 200


def test_massassign_exercise_toggle(alice, base_url, set_hardened):
    resp = alice.patch(f"{base_url}/api/account", json={"billing_rate": 0.01}, timeout=10)
    assert "flag" in resp.json()

    set_hardened("MASSASSIGN_EXERCISE", True)

    resp = alice.patch(f"{base_url}/api/account", json={"billing_rate": 0.02}, timeout=10)
    assert resp.status_code == 400  # field silently dropped, nothing left to update


def test_role_escalation_bonus_toggle(farid, base_url, set_hardened):
    # Don't assume farid starts as 'customer' -- on a persistent, shared
    # instance, a PRIOR run of this same test (or a manual poke) may have
    # left the role changed if it failed before reaching its own revert
    # line. Reset first, unconditionally, before asserting anything.
    farid.patch(f"{base_url}/api/account", json={"role": "customer"}, timeout=10)

    try:
        resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
        assert "role_flag" in resp.json()
    finally:
        # Always attempt to revert, even if the assertion above failed --
        # a plain statement after the assert (as this test had before)
        # never runs on failure, which is how farid got stuck as admin
        # in the first place.
        farid.patch(f"{base_url}/api/account", json={"role": "customer"}, timeout=10)

    set_hardened("ROLE_ESCALATION_BONUS", True)

    resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
    assert resp.status_code == 400
