BUSLOGIC_TEACH = "FLAG{HIDDEN_WALLET}"       # /recharge, client-controlled units_credited
BUSLOGIC_EXERCISE = "FLAG{SUNBURST_TALLY}"   # /solar, exported_kwh with no plausibility cap


def test_buslogic_teach_recharge(alice, base_url):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert resp.status_code == 200
    assert BUSLOGIC_TEACH in resp.text


def test_buslogic_exercise_solar(alice, base_url):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert resp.status_code == 200
    assert BUSLOGIC_EXERCISE in resp.text
