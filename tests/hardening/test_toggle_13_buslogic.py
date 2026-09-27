def test_buslogic_teach_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_TEACH", True)

    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert "FLAG{" not in resp.text


def test_buslogic_exercise_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_EXERCISE", True)

    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert "FLAG{" not in resp.text
