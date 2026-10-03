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
    try:
        resp = alice.patch(f"{base_url}/api/account", json={"billing_rate": 0.01}, timeout=10)
        assert "flag" in resp.json()
    finally:
        alice.patch(f"{base_url}/api/account", json={"billing_rate": 0.28}, timeout=10)

    set_hardened("MASSASSIGN_EXERCISE", True)

    resp = alice.patch(f"{base_url}/api/account", json={"billing_rate": 0.02}, timeout=10)
    assert resp.status_code == 400  # field silently dropped, nothing left to update


def test_role_escalation_bonus_toggle(farid, base_url, set_hardened):
    farid.patch(f"{base_url}/api/account", json={"role": "customer"}, timeout=10)

    try:
        resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
        assert "role_flag" in resp.json()
    finally:
        farid.patch(f"{base_url}/api/account", json={"role": "customer"}, timeout=10)

    set_hardened("ROLE_ESCALATION_BONUS", True)

    resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
    assert resp.status_code == 400


def test_account_idor_bonus_toggle(farid, base_url, set_hardened):
    resp = farid.patch(
        f"{base_url}/api/account",
        json={"account_email": "devon.reed@example.com", "phone": "555-0199"},
        timeout=10,
    )
    assert "idor_flag" in resp.json()

    set_hardened("ACCOUNT_IDOR_BONUS", True)

    # account_email is ignored outright once hardened -- lands on
    # farid's own row instead, same pattern as billing_rate/role above.
    resp = farid.patch(
        f"{base_url}/api/account",
        json={"account_email": "devon.reed@example.com", "phone": "555-0177"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "idor_flag" not in resp.json()
