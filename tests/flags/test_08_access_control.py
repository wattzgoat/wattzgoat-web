

def test_idor_teach(devon, base_url, redeem_flag_fn):
    # meter id 2 belongs to a different seeded customer than devon.
    resp = devon.get(f"{base_url}/api/meters/2/readings", timeout=10)
    assert resp.status_code == 200
    flag = resp.json().get("flag")
    assert flag
    assert redeem_flag_fn(devon, base_url, flag)


def test_massassign_exercise(farid, base_url, redeem_flag_fn):
    resp = farid.patch(f"{base_url}/api/account", json={"billing_rate": 0.01}, timeout=10)
    assert resp.status_code == 200
    flag = resp.json().get("flag")
    assert flag
    assert redeem_flag_fn(farid, base_url, flag)


def test_role_escalation_bonus(farid, base_url, redeem_flag_fn):
    resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
    assert resp.status_code == 200
    flag = resp.json().get("role_flag")
    assert flag
    assert redeem_flag_fn(farid, base_url, flag)


def test_account_idor_bonus(farid, base_url, extract_flag_fn, redeem_flag_fn):
    resp = farid.patch(
        f"{base_url}/api/account",
        json={"account_email": "devon.reed@example.com", "phone": "555-0199"},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = resp.json().get("idor_flag")
    assert flag
    assert redeem_flag_fn(farid, base_url, flag)
    # Only the IDOR flag -- not also massassign/role, even if this same
    # request had touched billing_rate/role.
    assert "flag" not in resp.json()
    assert "role_flag" not in resp.json()


def test_account_idor_bonus_own_email_is_not_idor(alice, base_url):
    # account_email pointed back at the caller's own address (what the
    # rendered form actually sends every time) is a no-op, same as today.
    resp = alice.patch(
        f"{base_url}/api/account",
        json={"account_email": "alice.smith@example.com", "phone": "555-0100"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert "idor_flag" not in resp.json()
